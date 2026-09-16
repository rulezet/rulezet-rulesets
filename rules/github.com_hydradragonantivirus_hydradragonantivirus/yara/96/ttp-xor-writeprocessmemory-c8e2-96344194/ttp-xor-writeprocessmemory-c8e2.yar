rule TTP_XOR_WriteProcessMemory_c8e2 {
  strings:
    $key_c8e2 = { 9f 90 [2] ad b2 [2] ab 87 [2] 85 87 [2] ba 9b }

  condition:
    any of them
}