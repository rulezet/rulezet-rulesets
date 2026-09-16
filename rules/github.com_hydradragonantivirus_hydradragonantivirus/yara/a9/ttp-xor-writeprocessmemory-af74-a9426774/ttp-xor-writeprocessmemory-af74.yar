rule TTP_XOR_WriteProcessMemory_af74 {
  strings:
    $key_af74 = { f8 06 [2] ca 24 [2] cc 11 [2] e2 11 [2] dd 0d }

  condition:
    any of them
}