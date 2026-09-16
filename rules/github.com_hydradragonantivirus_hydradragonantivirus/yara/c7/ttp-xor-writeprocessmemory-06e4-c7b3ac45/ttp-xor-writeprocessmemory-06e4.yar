rule TTP_XOR_WriteProcessMemory_06e4 {
  strings:
    $key_06e4 = { 51 96 [2] 63 b4 [2] 65 81 [2] 4b 81 [2] 74 9d }

  condition:
    any of them
}