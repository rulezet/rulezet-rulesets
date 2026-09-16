rule TTP_XOR_WriteProcessMemory_05d0 {
  strings:
    $key_05d0 = { 52 a2 [2] 60 80 [2] 66 b5 [2] 48 b5 [2] 77 a9 }

  condition:
    any of them
}