rule TTP_XOR_WriteProcessMemory_af25 {
  strings:
    $key_af25 = { f8 57 [2] ca 75 [2] cc 40 [2] e2 40 [2] dd 5c }

  condition:
    any of them
}