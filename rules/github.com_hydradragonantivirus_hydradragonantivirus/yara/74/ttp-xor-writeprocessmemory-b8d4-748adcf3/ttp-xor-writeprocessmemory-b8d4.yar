rule TTP_XOR_WriteProcessMemory_b8d4 {
  strings:
    $key_b8d4 = { ef a6 [2] dd 84 [2] db b1 [2] f5 b1 [2] ca ad }

  condition:
    any of them
}