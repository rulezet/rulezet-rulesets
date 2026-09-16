rule TTP_XOR_WriteProcessMemory_34e4 {
  strings:
    $key_34e4 = { 63 96 [2] 51 b4 [2] 57 81 [2] 79 81 [2] 46 9d }

  condition:
    any of them
}