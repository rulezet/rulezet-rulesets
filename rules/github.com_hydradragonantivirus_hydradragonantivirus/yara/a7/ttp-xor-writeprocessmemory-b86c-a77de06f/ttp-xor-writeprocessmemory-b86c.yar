rule TTP_XOR_WriteProcessMemory_b86c {
  strings:
    $key_b86c = { ef 1e [2] dd 3c [2] db 09 [2] f5 09 [2] ca 15 }

  condition:
    any of them
}