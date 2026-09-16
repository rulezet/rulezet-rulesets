rule TTP_XOR_WriteProcessMemory_c82b {
  strings:
    $key_c82b = { 9f 59 [2] ad 7b [2] ab 4e [2] 85 4e [2] ba 52 }

  condition:
    any of them
}