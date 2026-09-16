rule TTP_XOR_WriteProcessMemory_7e0f {
  strings:
    $key_7e0f = { 29 7d [2] 1b 5f [2] 1d 6a [2] 33 6a [2] 0c 76 }

  condition:
    any of them
}