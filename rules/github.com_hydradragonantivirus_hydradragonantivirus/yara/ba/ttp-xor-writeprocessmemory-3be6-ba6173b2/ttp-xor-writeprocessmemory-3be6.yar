rule TTP_XOR_WriteProcessMemory_3be6 {
  strings:
    $key_3be6 = { 6c 94 [2] 5e b6 [2] 58 83 [2] 76 83 [2] 49 9f }

  condition:
    any of them
}