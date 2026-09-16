rule TTP_XOR_WriteProcessMemory_09c3 {
  strings:
    $key_09c3 = { 5e b1 [2] 6c 93 [2] 6a a6 [2] 44 a6 [2] 7b ba }

  condition:
    any of them
}