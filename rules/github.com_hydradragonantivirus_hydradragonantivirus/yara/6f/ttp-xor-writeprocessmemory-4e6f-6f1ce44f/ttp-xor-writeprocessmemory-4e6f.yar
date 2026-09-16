rule TTP_XOR_WriteProcessMemory_4e6f {
  strings:
    $key_4e6f = { 19 1d [2] 2b 3f [2] 2d 0a [2] 03 0a [2] 3c 16 }

  condition:
    any of them
}