rule TTP_XOR_WriteProcessMemory_08e6 {
  strings:
    $key_08e6 = { 5f 94 [2] 6d b6 [2] 6b 83 [2] 45 83 [2] 7a 9f }

  condition:
    any of them
}