rule TTP_XOR_WriteProcessMemory_e9e1 {
  strings:
    $key_e9e1 = { be 93 [2] 8c b1 [2] 8a 84 [2] a4 84 [2] 9b 98 }

  condition:
    any of them
}