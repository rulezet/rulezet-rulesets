rule TTP_XOR_WriteProcessMemory_2a26 {
  strings:
    $key_2a26 = { 7d 54 [2] 4f 76 [2] 49 43 [2] 67 43 [2] 58 5f }

  condition:
    any of them
}