rule TTP_XOR_WriteProcessMemory_64a6 {
  strings:
    $key_64a6 = { 33 d4 [2] 01 f6 [2] 07 c3 [2] 29 c3 [2] 16 df }

  condition:
    any of them
}