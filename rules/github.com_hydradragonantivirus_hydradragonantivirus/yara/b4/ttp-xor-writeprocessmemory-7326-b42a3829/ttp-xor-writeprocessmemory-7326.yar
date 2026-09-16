rule TTP_XOR_WriteProcessMemory_7326 {
  strings:
    $key_7326 = { 24 54 [2] 16 76 [2] 10 43 [2] 3e 43 [2] 01 5f }

  condition:
    any of them
}