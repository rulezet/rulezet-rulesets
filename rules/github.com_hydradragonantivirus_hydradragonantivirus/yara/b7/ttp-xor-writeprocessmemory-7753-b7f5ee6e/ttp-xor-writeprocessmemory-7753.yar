rule TTP_XOR_WriteProcessMemory_7753 {
  strings:
    $key_7753 = { 20 21 [2] 12 03 [2] 14 36 [2] 3a 36 [2] 05 2a }

  condition:
    any of them
}