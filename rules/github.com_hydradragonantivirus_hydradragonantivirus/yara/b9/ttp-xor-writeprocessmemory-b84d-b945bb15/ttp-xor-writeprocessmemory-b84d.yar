rule TTP_XOR_WriteProcessMemory_b84d {
  strings:
    $key_b84d = { ef 3f [2] dd 1d [2] db 28 [2] f5 28 [2] ca 34 }

  condition:
    any of them
}