rule TTP_XOR_WriteProcessMemory_6e0f {
  strings:
    $key_6e0f = { 39 7d [2] 0b 5f [2] 0d 6a [2] 23 6a [2] 1c 76 }

  condition:
    any of them
}