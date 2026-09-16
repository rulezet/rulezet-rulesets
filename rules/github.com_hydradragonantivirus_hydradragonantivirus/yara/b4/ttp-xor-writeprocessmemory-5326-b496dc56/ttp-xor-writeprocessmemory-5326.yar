rule TTP_XOR_WriteProcessMemory_5326 {
  strings:
    $key_5326 = { 04 54 [2] 36 76 [2] 30 43 [2] 1e 43 [2] 21 5f }

  condition:
    any of them
}