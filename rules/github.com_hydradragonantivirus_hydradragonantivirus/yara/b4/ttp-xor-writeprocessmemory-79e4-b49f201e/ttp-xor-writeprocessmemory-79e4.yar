rule TTP_XOR_WriteProcessMemory_79e4 {
  strings:
    $key_79e4 = { 2e 96 [2] 1c b4 [2] 1a 81 [2] 34 81 [2] 0b 9d }

  condition:
    any of them
}