rule TTP_XOR_WriteProcessMemory_607f {
  strings:
    $key_607f = { 37 0d [2] 05 2f [2] 03 1a [2] 2d 1a [2] 12 06 }

  condition:
    any of them
}