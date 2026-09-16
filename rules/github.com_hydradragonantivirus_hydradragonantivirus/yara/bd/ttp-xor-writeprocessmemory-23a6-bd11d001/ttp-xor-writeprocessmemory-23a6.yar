rule TTP_XOR_WriteProcessMemory_23a6 {
  strings:
    $key_23a6 = { 74 d4 [2] 46 f6 [2] 40 c3 [2] 6e c3 [2] 51 df }

  condition:
    any of them
}