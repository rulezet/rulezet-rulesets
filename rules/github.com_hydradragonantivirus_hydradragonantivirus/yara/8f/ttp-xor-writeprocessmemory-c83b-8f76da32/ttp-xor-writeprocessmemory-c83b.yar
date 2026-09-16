rule TTP_XOR_WriteProcessMemory_c83b {
  strings:
    $key_c83b = { 9f 49 [2] ad 6b [2] ab 5e [2] 85 5e [2] ba 42 }

  condition:
    any of them
}