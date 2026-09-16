rule TTP_XOR_WriteProcessMemory_2326 {
  strings:
    $key_2326 = { 74 54 [2] 46 76 [2] 40 43 [2] 6e 43 [2] 51 5f }

  condition:
    any of them
}