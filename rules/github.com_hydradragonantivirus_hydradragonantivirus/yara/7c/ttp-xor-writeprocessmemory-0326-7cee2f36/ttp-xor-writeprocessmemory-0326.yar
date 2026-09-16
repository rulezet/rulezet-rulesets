rule TTP_XOR_WriteProcessMemory_0326 {
  strings:
    $key_0326 = { 54 54 [2] 66 76 [2] 60 43 [2] 4e 43 [2] 71 5f }

  condition:
    any of them
}