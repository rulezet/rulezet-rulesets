rule TTP_XOR_WriteProcessMemory_c82e {
  strings:
    $key_c82e = { 9f 5c [2] ad 7e [2] ab 4b [2] 85 4b [2] ba 57 }

  condition:
    any of them
}