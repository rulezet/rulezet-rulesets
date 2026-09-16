rule TTP_XOR_WriteProcessMemory_60e3 {
  strings:
    $key_60e3 = { 37 91 [2] 05 b3 [2] 03 86 [2] 2d 86 [2] 12 9a }

  condition:
    any of them
}