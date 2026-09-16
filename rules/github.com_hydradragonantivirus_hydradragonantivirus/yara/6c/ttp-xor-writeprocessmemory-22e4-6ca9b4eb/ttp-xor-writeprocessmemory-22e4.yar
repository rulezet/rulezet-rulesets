rule TTP_XOR_WriteProcessMemory_22e4 {
  strings:
    $key_22e4 = { 75 96 [2] 47 b4 [2] 41 81 [2] 6f 81 [2] 50 9d }

  condition:
    any of them
}