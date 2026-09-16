rule TTP_XOR_WriteProcessMemory_05d1 {
  strings:
    $key_05d1 = { 52 a3 [2] 60 81 [2] 66 b4 [2] 48 b4 [2] 77 a8 }

  condition:
    any of them
}