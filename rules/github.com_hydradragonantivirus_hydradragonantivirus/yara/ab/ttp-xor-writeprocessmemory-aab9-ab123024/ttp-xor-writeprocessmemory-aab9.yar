rule TTP_XOR_WriteProcessMemory_aab9 {
  strings:
    $key_aab9 = { fd cb [2] cf e9 [2] c9 dc [2] e7 dc [2] d8 c0 }

  condition:
    any of them
}