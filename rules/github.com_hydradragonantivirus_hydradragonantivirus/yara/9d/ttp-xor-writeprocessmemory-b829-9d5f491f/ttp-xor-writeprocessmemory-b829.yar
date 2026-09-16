rule TTP_XOR_WriteProcessMemory_b829 {
  strings:
    $key_b829 = { ef 5b [2] dd 79 [2] db 4c [2] f5 4c [2] ca 50 }

  condition:
    any of them
}