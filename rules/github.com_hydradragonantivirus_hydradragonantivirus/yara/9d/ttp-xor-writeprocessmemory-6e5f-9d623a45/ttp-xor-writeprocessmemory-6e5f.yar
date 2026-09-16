rule TTP_XOR_WriteProcessMemory_6e5f {
  strings:
    $key_6e5f = { 39 2d [2] 0b 0f [2] 0d 3a [2] 23 3a [2] 1c 26 }

  condition:
    any of them
}