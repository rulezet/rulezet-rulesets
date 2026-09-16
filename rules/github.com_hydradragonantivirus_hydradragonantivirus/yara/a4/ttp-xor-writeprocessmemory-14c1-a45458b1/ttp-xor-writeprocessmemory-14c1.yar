rule TTP_XOR_WriteProcessMemory_14c1 {
  strings:
    $key_14c1 = { 43 b3 [2] 71 91 [2] 77 a4 [2] 59 a4 [2] 66 b8 }

  condition:
    any of them
}