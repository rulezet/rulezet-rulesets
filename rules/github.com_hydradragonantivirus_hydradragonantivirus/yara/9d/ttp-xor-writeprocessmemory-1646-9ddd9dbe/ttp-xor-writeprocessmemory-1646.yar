rule TTP_XOR_WriteProcessMemory_1646 {
  strings:
    $key_1646 = { 41 34 [2] 73 16 [2] 75 23 [2] 5b 23 [2] 64 3f }

  condition:
    any of them
}