rule TTP_XOR_WriteProcessMemory_b8e5 {
  strings:
    $key_b8e5 = { ef 97 [2] dd b5 [2] db 80 [2] f5 80 [2] ca 9c }

  condition:
    any of them
}