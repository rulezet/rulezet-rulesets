rule TTP_XOR_WriteProcessMemory_7e5f {
  strings:
    $key_7e5f = { 29 2d [2] 1b 0f [2] 1d 3a [2] 33 3a [2] 0c 26 }

  condition:
    any of them
}