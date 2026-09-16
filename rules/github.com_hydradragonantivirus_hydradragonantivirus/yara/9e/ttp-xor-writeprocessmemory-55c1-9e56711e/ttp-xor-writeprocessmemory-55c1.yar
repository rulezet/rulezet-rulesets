rule TTP_XOR_WriteProcessMemory_55c1 {
  strings:
    $key_55c1 = { 02 b3 [2] 30 91 [2] 36 a4 [2] 18 a4 [2] 27 b8 }

  condition:
    any of them
}