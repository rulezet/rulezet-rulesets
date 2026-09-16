rule TTP_XOR_WriteProcessMemory_4e7f {
  strings:
    $key_4e7f = { 19 0d [2] 2b 2f [2] 2d 1a [2] 03 1a [2] 3c 06 }

  condition:
    any of them
}