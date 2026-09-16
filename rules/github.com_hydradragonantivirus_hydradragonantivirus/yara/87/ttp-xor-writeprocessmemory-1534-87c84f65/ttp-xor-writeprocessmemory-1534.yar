rule TTP_XOR_WriteProcessMemory_1534 {
  strings:
    $key_1534 = { 42 46 [2] 70 64 [2] 76 51 [2] 58 51 [2] 67 4d }

  condition:
    any of them
}