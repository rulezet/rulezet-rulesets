rule TTP_XOR_WriteProcessMemory_aab1 {
  strings:
    $key_aab1 = { fd c3 [2] cf e1 [2] c9 d4 [2] e7 d4 [2] d8 c8 }

  condition:
    any of them
}