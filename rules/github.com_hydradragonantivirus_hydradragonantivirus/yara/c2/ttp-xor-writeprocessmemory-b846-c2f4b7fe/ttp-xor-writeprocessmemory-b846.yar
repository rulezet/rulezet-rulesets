rule TTP_XOR_WriteProcessMemory_b846 {
  strings:
    $key_b846 = { ef 34 [2] dd 16 [2] db 23 [2] f5 23 [2] ca 3f }

  condition:
    any of them
}