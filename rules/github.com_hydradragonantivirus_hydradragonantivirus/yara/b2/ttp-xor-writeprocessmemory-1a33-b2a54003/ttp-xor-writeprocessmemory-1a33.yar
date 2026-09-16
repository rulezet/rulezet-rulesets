rule TTP_XOR_WriteProcessMemory_1a33 {
  strings:
    $key_1a33 = { 4d 41 [2] 7f 63 [2] 79 56 [2] 57 56 [2] 68 4a }

  condition:
    any of them
}