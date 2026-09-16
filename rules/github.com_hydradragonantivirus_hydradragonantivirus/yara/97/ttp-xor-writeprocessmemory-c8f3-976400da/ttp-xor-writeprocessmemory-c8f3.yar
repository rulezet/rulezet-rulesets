rule TTP_XOR_WriteProcessMemory_c8f3 {
  strings:
    $key_c8f3 = { 9f 81 [2] ad a3 [2] ab 96 [2] 85 96 [2] ba 8a }

  condition:
    any of them
}