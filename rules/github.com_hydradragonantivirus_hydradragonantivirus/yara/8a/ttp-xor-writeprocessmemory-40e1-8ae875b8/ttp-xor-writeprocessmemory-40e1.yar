rule TTP_XOR_WriteProcessMemory_40e1 {
  strings:
    $key_40e1 = { 17 93 [2] 25 b1 [2] 23 84 [2] 0d 84 [2] 32 98 }

  condition:
    any of them
}