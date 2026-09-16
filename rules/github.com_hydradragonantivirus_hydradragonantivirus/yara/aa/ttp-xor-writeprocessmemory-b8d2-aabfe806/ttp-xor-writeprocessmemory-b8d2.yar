rule TTP_XOR_WriteProcessMemory_b8d2 {
  strings:
    $key_b8d2 = { ef a0 [2] dd 82 [2] db b7 [2] f5 b7 [2] ca ab }

  condition:
    any of them
}