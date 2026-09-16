rule TTP_XOR_WriteProcessMemory_cf95 {
  strings:
    $key_cf95 = { 98 e7 [2] aa c5 [2] ac f0 [2] 82 f0 [2] bd ec }

  condition:
    any of them
}