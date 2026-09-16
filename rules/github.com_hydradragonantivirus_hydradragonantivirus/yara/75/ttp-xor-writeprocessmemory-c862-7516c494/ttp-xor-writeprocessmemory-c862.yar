rule TTP_XOR_WriteProcessMemory_c862 {
  strings:
    $key_c862 = { 9f 10 [2] ad 32 [2] ab 07 [2] 85 07 [2] ba 1b }

  condition:
    any of them
}