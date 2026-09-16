rule TTP_XOR_WriteProcessMemory_b840 {
  strings:
    $key_b840 = { ef 32 [2] dd 10 [2] db 25 [2] f5 25 [2] ca 39 }

  condition:
    any of them
}