rule TTP_XOR_WriteProcessMemory_06e6 {
  strings:
    $key_06e6 = { 51 94 [2] 63 b6 [2] 65 83 [2] 4b 83 [2] 74 9f }

  condition:
    any of them
}