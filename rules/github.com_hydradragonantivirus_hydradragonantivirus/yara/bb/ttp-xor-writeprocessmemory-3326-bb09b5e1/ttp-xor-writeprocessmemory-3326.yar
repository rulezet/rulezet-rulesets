rule TTP_XOR_WriteProcessMemory_3326 {
  strings:
    $key_3326 = { 64 54 [2] 56 76 [2] 50 43 [2] 7e 43 [2] 41 5f }

  condition:
    any of them
}