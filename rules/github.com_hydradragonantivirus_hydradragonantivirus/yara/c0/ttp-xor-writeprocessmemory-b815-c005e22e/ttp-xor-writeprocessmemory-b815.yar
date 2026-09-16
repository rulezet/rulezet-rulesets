rule TTP_XOR_WriteProcessMemory_b815 {
  strings:
    $key_b815 = { ef 67 [2] dd 45 [2] db 70 [2] f5 70 [2] ca 6c }

  condition:
    any of them
}