rule TTP_XOR_WriteProcessMemory_15e4 {
  strings:
    $key_15e4 = { 42 96 [2] 70 b4 [2] 76 81 [2] 58 81 [2] 67 9d }

  condition:
    any of them
}