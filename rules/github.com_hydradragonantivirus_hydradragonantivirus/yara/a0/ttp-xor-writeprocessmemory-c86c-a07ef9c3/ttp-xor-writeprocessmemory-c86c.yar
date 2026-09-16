rule TTP_XOR_WriteProcessMemory_c86c {
  strings:
    $key_c86c = { 9f 1e [2] ad 3c [2] ab 09 [2] 85 09 [2] ba 15 }

  condition:
    any of them
}