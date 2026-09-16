rule TTP_XOR_WriteProcessMemory_b83c {
  strings:
    $key_b83c = { ef 4e [2] dd 6c [2] db 59 [2] f5 59 [2] ca 45 }

  condition:
    any of them
}