rule TTP_XOR_WriteProcessMemory_b8d6 {
  strings:
    $key_b8d6 = { ef a4 [2] dd 86 [2] db b3 [2] f5 b3 [2] ca af }

  condition:
    any of them
}