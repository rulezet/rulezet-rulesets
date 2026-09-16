rule TTP_XOR_WriteProcessMemory_1ee4 {
  strings:
    $key_1ee4 = { 49 96 [2] 7b b4 [2] 7d 81 [2] 53 81 [2] 6c 9d }

  condition:
    any of them
}