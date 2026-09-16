rule TTP_XOR_WriteProcessMemory_2a73 {
  strings:
    $key_2a73 = { 7d 01 [2] 4f 23 [2] 49 16 [2] 67 16 [2] 58 0a }

  condition:
    any of them
}