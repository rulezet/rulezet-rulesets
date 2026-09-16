rule TTP_XOR_WriteProcessMemory_af12 {
  strings:
    $key_af12 = { f8 60 [2] ca 42 [2] cc 77 [2] e2 77 [2] dd 6b }

  condition:
    any of them
}