rule TTP_XOR_WriteProcessMemory_b848 {
  strings:
    $key_b848 = { ef 3a [2] dd 18 [2] db 2d [2] f5 2d [2] ca 31 }

  condition:
    any of them
}