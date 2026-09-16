rule TTP_XOR_WriteProcessMemory_b8e2 {
  strings:
    $key_b8e2 = { ef 90 [2] dd b2 [2] db 87 [2] f5 87 [2] ca 9b }

  condition:
    any of them
}