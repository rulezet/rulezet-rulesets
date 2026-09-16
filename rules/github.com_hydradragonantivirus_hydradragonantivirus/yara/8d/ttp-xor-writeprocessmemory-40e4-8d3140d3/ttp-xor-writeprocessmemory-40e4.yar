rule TTP_XOR_WriteProcessMemory_40e4 {
  strings:
    $key_40e4 = { 17 96 [2] 25 b4 [2] 23 81 [2] 0d 81 [2] 32 9d }

  condition:
    any of them
}