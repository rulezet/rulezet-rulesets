rule TTP_XOR_WriteProcessMemory_36a6 {
  strings:
    $key_36a6 = { 61 d4 [2] 53 f6 [2] 55 c3 [2] 7b c3 [2] 44 df }

  condition:
    any of them
}