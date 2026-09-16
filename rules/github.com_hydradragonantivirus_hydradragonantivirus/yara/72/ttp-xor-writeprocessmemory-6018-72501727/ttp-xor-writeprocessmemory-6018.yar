rule TTP_XOR_WriteProcessMemory_6018 {
  strings:
    $key_6018 = { 37 6a [2] 05 48 [2] 03 7d [2] 2d 7d [2] 12 61 }

  condition:
    any of them
}