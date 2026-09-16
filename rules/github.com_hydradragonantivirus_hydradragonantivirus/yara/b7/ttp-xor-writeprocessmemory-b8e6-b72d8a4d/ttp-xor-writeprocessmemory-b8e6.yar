rule TTP_XOR_WriteProcessMemory_b8e6 {
  strings:
    $key_b8e6 = { ef 94 [2] dd b6 [2] db 83 [2] f5 83 [2] ca 9f }

  condition:
    any of them
}