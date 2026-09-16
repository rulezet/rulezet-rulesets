rule TTP_XOR_WriteProcessMemory_13e4 {
  strings:
    $key_13e4 = { 44 96 [2] 76 b4 [2] 70 81 [2] 5e 81 [2] 61 9d }

  condition:
    any of them
}