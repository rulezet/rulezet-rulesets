rule TTP_XOR_WriteProcessMemory_c8e1 {
  strings:
    $key_c8e1 = { 9f 93 [2] ad b1 [2] ab 84 [2] 85 84 [2] ba 98 }

  condition:
    any of them
}