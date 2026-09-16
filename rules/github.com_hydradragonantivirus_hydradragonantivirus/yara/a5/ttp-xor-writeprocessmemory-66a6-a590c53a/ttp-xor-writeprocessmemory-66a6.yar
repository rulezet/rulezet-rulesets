rule TTP_XOR_WriteProcessMemory_66a6 {
  strings:
    $key_66a6 = { 31 d4 [2] 03 f6 [2] 05 c3 [2] 2b c3 [2] 14 df }

  condition:
    any of them
}