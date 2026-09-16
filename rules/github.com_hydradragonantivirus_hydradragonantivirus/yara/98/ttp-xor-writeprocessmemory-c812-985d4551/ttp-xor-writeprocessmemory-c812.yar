rule TTP_XOR_WriteProcessMemory_c812 {
  strings:
    $key_c812 = { 9f 60 [2] ad 42 [2] ab 77 [2] 85 77 [2] ba 6b }

  condition:
    any of them
}