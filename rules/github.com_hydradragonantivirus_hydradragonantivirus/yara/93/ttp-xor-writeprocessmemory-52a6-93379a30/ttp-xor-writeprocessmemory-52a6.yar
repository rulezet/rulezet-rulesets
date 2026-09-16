rule TTP_XOR_WriteProcessMemory_52a6 {
  strings:
    $key_52a6 = { 05 d4 [2] 37 f6 [2] 31 c3 [2] 1f c3 [2] 20 df }

  condition:
    any of them
}