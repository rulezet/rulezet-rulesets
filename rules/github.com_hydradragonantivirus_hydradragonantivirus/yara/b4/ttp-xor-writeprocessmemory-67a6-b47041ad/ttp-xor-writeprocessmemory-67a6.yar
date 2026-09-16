rule TTP_XOR_WriteProcessMemory_67a6 {
  strings:
    $key_67a6 = { 30 d4 [2] 02 f6 [2] 04 c3 [2] 2a c3 [2] 15 df }

  condition:
    any of them
}