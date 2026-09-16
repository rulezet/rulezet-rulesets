rule TTP_XOR_WriteProcessMemory_8326 {
  strings:
    $key_8326 = { d4 54 [2] e6 76 [2] e0 43 [2] ce 43 [2] f1 5f }

  condition:
    any of them
}