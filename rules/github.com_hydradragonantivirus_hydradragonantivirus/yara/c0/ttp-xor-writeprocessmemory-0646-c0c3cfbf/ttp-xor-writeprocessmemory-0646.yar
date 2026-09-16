rule TTP_XOR_WriteProcessMemory_0646 {
  strings:
    $key_0646 = { 51 34 [2] 63 16 [2] 65 23 [2] 4b 23 [2] 74 3f }

  condition:
    any of them
}