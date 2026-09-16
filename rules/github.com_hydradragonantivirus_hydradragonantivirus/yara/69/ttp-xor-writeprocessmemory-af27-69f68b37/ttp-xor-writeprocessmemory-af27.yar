rule TTP_XOR_WriteProcessMemory_af27 {
  strings:
    $key_af27 = { f8 55 [2] ca 77 [2] cc 42 [2] e2 42 [2] dd 5e }

  condition:
    any of them
}