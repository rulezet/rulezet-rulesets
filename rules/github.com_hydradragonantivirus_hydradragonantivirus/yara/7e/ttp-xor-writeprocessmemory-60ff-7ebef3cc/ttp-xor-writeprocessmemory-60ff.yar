rule TTP_XOR_WriteProcessMemory_60ff {
  strings:
    $key_60ff = { 37 8d [2] 05 af [2] 03 9a [2] 2d 9a [2] 12 86 }

  condition:
    any of them
}