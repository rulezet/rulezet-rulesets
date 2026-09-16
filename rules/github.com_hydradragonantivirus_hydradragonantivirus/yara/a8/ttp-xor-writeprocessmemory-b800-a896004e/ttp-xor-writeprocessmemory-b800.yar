rule TTP_XOR_WriteProcessMemory_b800 {
  strings:
    $key_b800 = { ef 72 [2] dd 50 [2] db 65 [2] f5 65 [2] ca 79 }

  condition:
    any of them
}