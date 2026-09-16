rule TTP_XOR_WriteProcessMemory_b8c5 {
  strings:
    $key_b8c5 = { ef b7 [2] dd 95 [2] db a0 [2] f5 a0 [2] ca bc }

  condition:
    any of them
}