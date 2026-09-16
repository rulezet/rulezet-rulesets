rule TTP_XOR_WriteProcessMemory_b80b {
  strings:
    $key_b80b = { ef 79 [2] dd 5b [2] db 6e [2] f5 6e [2] ca 72 }

  condition:
    any of them
}