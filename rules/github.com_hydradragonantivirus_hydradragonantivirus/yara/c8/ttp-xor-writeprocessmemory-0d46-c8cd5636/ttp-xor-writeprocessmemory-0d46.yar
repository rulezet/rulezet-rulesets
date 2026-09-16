rule TTP_XOR_WriteProcessMemory_0d46 {
  strings:
    $key_0d46 = { 5a 34 [2] 68 16 [2] 6e 23 [2] 40 23 [2] 7f 3f }

  condition:
    any of them
}