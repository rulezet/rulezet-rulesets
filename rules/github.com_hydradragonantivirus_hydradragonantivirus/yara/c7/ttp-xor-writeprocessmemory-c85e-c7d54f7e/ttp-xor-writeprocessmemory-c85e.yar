rule TTP_XOR_WriteProcessMemory_c85e {
  strings:
    $key_c85e = { 9f 2c [2] ad 0e [2] ab 3b [2] 85 3b [2] ba 27 }

  condition:
    any of them
}