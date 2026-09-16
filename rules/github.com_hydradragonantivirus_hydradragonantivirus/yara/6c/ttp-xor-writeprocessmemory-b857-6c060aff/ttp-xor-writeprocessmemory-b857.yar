rule TTP_XOR_WriteProcessMemory_b857 {
  strings:
    $key_b857 = { ef 25 [2] dd 07 [2] db 32 [2] f5 32 [2] ca 2e }

  condition:
    any of them
}