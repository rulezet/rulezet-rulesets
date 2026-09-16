rule TTP_XOR_WriteProcessMemory_b802 {
  strings:
    $key_b802 = { ef 70 [2] dd 52 [2] db 67 [2] f5 67 [2] ca 7b }

  condition:
    any of them
}