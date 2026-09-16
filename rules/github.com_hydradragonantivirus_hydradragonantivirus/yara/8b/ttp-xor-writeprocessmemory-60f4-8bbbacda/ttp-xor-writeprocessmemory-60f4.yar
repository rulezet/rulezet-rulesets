rule TTP_XOR_WriteProcessMemory_60f4 {
  strings:
    $key_60f4 = { 37 86 [2] 05 a4 [2] 03 91 [2] 2d 91 [2] 12 8d }

  condition:
    any of them
}