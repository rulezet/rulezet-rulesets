rule TTP_XOR_WriteProcessMemory_b855 {
  strings:
    $key_b855 = { ef 27 [2] dd 05 [2] db 30 [2] f5 30 [2] ca 2c }

  condition:
    any of them
}