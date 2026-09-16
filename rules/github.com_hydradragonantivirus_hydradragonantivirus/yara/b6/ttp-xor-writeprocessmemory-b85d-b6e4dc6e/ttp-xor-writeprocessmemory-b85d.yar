rule TTP_XOR_WriteProcessMemory_b85d {
  strings:
    $key_b85d = { ef 2f [2] dd 0d [2] db 38 [2] f5 38 [2] ca 24 }

  condition:
    any of them
}