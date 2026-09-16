rule TTP_XOR_WriteProcessMemory_aff0 {
  strings:
    $key_aff0 = { f8 82 [2] ca a0 [2] cc 95 [2] e2 95 [2] dd 89 }

  condition:
    any of them
}