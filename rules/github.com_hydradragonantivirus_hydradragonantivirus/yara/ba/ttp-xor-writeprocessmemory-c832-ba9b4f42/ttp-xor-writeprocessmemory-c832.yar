rule TTP_XOR_WriteProcessMemory_c832 {
  strings:
    $key_c832 = { 9f 40 [2] ad 62 [2] ab 57 [2] 85 57 [2] ba 4b }

  condition:
    any of them
}