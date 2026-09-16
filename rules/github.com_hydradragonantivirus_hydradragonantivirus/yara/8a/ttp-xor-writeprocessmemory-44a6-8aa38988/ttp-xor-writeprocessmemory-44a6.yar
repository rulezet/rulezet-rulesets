rule TTP_XOR_WriteProcessMemory_44a6 {
  strings:
    $key_44a6 = { 13 d4 [2] 21 f6 [2] 27 c3 [2] 09 c3 [2] 36 df }

  condition:
    any of them
}