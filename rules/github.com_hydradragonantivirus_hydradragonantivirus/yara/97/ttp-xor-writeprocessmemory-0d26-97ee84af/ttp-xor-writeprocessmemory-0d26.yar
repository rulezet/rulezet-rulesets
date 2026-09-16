rule TTP_XOR_WriteProcessMemory_0d26 {
  strings:
    $key_0d26 = { 5a 54 [2] 68 76 [2] 6e 43 [2] 40 43 [2] 7f 5f }

  condition:
    any of them
}