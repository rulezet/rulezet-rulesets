rule TTP_XOR_WriteProcessMemory_c835 {
  strings:
    $key_c835 = { 9f 47 [2] ad 65 [2] ab 50 [2] 85 50 [2] ba 4c }

  condition:
    any of them
}