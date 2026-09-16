rule TTP_XOR_WriteProcessMemory_3946 {
  strings:
    $key_3946 = { 6e 34 [2] 5c 16 [2] 5a 23 [2] 74 23 [2] 4b 3f }

  condition:
    any of them
}