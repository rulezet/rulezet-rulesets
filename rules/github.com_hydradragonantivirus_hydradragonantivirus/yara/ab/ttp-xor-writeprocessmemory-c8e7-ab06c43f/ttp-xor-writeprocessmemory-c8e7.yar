rule TTP_XOR_WriteProcessMemory_c8e7 {
  strings:
    $key_c8e7 = { 9f 95 [2] ad b7 [2] ab 82 [2] 85 82 [2] ba 9e }

  condition:
    any of them
}