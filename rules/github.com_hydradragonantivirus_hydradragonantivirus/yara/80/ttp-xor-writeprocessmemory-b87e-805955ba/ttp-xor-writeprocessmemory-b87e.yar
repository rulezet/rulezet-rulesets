rule TTP_XOR_WriteProcessMemory_b87e {
  strings:
    $key_b87e = { ef 0c [2] dd 2e [2] db 1b [2] f5 1b [2] ca 07 }

  condition:
    any of them
}