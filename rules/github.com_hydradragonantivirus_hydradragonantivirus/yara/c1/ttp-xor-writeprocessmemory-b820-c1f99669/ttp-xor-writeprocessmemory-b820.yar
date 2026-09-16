rule TTP_XOR_WriteProcessMemory_b820 {
  strings:
    $key_b820 = { ef 52 [2] dd 70 [2] db 45 [2] f5 45 [2] ca 59 }

  condition:
    any of them
}