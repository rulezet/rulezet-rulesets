rule TTP_XOR_WriteProcessMemory_aab4 {
  strings:
    $key_aab4 = { fd c6 [2] cf e4 [2] c9 d1 [2] e7 d1 [2] d8 cd }

  condition:
    any of them
}