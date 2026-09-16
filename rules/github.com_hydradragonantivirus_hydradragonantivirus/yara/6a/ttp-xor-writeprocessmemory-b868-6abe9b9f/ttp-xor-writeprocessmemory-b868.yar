rule TTP_XOR_WriteProcessMemory_b868 {
  strings:
    $key_b868 = { ef 1a [2] dd 38 [2] db 0d [2] f5 0d [2] ca 11 }

  condition:
    any of them
}