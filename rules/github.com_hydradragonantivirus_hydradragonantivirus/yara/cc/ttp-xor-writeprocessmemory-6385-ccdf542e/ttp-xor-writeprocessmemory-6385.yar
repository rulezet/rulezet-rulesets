rule TTP_XOR_WriteProcessMemory_6385 {
  strings:
    $key_6385 = { 34 f7 [2] 06 d5 [2] 00 e0 [2] 2e e0 [2] 11 fc }

  condition:
    any of them
}