rule TTP_XOR_WriteProcessMemory_11e1 {
  strings:
    $key_11e1 = { 46 93 [2] 74 b1 [2] 72 84 [2] 5c 84 [2] 63 98 }

  condition:
    any of them
}