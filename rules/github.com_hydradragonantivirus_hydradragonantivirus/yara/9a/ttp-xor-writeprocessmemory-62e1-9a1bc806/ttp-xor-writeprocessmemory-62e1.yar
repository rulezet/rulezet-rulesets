rule TTP_XOR_WriteProcessMemory_62e1 {
  strings:
    $key_62e1 = { 35 93 [2] 07 b1 [2] 01 84 [2] 2f 84 [2] 10 98 }

  condition:
    any of them
}