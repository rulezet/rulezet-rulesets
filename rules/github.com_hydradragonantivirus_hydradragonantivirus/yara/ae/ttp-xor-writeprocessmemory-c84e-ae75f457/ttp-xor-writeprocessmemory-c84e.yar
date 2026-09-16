rule TTP_XOR_WriteProcessMemory_c84e {
  strings:
    $key_c84e = { 9f 3c [2] ad 1e [2] ab 2b [2] 85 2b [2] ba 37 }

  condition:
    any of them
}