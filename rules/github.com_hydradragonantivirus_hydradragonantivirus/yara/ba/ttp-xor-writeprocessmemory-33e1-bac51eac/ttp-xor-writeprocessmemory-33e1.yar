rule TTP_XOR_WriteProcessMemory_33e1 {
  strings:
    $key_33e1 = { 64 93 [2] 56 b1 [2] 50 84 [2] 7e 84 [2] 41 98 }

  condition:
    any of them
}