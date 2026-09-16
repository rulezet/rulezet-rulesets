rule TTP_XOR_WriteProcessMemory_b81c {
  strings:
    $key_b81c = { ef 6e [2] dd 4c [2] db 79 [2] f5 79 [2] ca 65 }

  condition:
    any of them
}