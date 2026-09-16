rule TTP_XOR_WriteProcessMemory_b8c3 {
  strings:
    $key_b8c3 = { ef b1 [2] dd 93 [2] db a6 [2] f5 a6 [2] ca ba }

  condition:
    any of them
}