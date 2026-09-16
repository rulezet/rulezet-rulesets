rule TTP_XOR_WriteProcessMemory_02e4 {
  strings:
    $key_02e4 = { 55 96 [2] 67 b4 [2] 61 81 [2] 4f 81 [2] 70 9d }

  condition:
    any of them
}