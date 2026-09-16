rule TTP_XOR_WriteProcessMemory_1454 {
  strings:
    $key_1454 = { 43 26 [2] 71 04 [2] 77 31 [2] 59 31 [2] 66 2d }

  condition:
    any of them
}