rule TTP_XOR_WriteProcessMemory_b8eb {
  strings:
    $key_b8eb = { ef 99 [2] dd bb [2] db 8e [2] f5 8e [2] ca 92 }

  condition:
    any of them
}