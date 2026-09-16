rule TTP_XOR_WriteProcessMemory_5de1 {
  strings:
    $key_5de1 = { 0a 93 [2] 38 b1 [2] 3e 84 [2] 10 84 [2] 2f 98 }

  condition:
    any of them
}