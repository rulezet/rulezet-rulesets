rule TTP_XOR_WriteProcessMemory_79e1 {
  strings:
    $key_79e1 = { 2e 93 [2] 1c b1 [2] 1a 84 [2] 34 84 [2] 0b 98 }

  condition:
    any of them
}