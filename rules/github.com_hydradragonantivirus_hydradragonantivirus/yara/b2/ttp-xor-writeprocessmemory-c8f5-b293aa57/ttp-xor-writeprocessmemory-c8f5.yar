rule TTP_XOR_WriteProcessMemory_c8f5 {
  strings:
    $key_c8f5 = { 9f 87 [2] ad a5 [2] ab 90 [2] 85 90 [2] ba 8c }

  condition:
    any of them
}