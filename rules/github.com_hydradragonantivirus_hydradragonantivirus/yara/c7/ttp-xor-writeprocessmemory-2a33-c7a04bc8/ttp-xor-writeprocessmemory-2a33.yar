rule TTP_XOR_WriteProcessMemory_2a33 {
  strings:
    $key_2a33 = { 7d 41 [2] 4f 63 [2] 49 56 [2] 67 56 [2] 58 4a }

  condition:
    any of them
}