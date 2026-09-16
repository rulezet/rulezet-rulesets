rule TTP_XOR_WriteProcessMemory_c81b {
  strings:
    $key_c81b = { 9f 69 [2] ad 4b [2] ab 7e [2] 85 7e [2] ba 62 }

  condition:
    any of them
}