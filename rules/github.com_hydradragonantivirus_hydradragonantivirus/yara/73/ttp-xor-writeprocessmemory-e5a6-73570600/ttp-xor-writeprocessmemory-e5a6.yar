rule TTP_XOR_WriteProcessMemory_e5a6 {
  strings:
    $key_e5a6 = { b2 d4 [2] 80 f6 [2] 86 c3 [2] a8 c3 [2] 97 df }

  condition:
    any of them
}