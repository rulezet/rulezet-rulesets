rule TTP_XOR_WriteProcessMemory_c8f6 {
  strings:
    $key_c8f6 = { 9f 84 [2] ad a6 [2] ab 93 [2] 85 93 [2] ba 8f }

  condition:
    any of them
}