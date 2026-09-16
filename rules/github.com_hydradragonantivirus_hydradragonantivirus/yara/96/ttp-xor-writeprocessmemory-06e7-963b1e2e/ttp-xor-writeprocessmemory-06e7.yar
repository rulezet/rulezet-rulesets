rule TTP_XOR_WriteProcessMemory_06e7 {
  strings:
    $key_06e7 = { 51 95 [2] 63 b7 [2] 65 82 [2] 4b 82 [2] 74 9e }

  condition:
    any of them
}