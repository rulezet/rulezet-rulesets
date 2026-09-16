rule TTP_XOR_WriteProcessMemory_b84c {
  strings:
    $key_b84c = { ef 3e [2] dd 1c [2] db 29 [2] f5 29 [2] ca 35 }

  condition:
    any of them
}