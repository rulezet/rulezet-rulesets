rule TTP_XOR_WriteProcessMemory_c80b {
  strings:
    $key_c80b = { 9f 79 [2] ad 5b [2] ab 6e [2] 85 6e [2] ba 72 }

  condition:
    any of them
}