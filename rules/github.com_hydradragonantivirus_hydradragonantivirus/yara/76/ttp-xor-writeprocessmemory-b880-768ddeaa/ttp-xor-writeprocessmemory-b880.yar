rule TTP_XOR_WriteProcessMemory_b880 {
  strings:
    $key_b880 = { ef f2 [2] dd d0 [2] db e5 [2] f5 e5 [2] ca f9 }

  condition:
    any of them
}