rule TTP_XOR_WriteProcessMemory_b835 {
  strings:
    $key_b835 = { ef 47 [2] dd 65 [2] db 50 [2] f5 50 [2] ca 4c }

  condition:
    any of them
}