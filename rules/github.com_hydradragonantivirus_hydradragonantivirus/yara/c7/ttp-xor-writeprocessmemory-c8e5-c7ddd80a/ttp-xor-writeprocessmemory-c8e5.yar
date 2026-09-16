rule TTP_XOR_WriteProcessMemory_c8e5 {
  strings:
    $key_c8e5 = { 9f 97 [2] ad b5 [2] ab 80 [2] 85 80 [2] ba 9c }

  condition:
    any of them
}