rule TTP_XOR_WriteProcessMemory_b85c {
  strings:
    $key_b85c = { ef 2e [2] dd 0c [2] db 39 [2] f5 39 [2] ca 25 }

  condition:
    any of them
}