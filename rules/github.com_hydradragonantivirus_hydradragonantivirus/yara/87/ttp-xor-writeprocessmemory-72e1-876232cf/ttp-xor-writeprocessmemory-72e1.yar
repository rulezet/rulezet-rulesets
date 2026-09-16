rule TTP_XOR_WriteProcessMemory_72e1 {
  strings:
    $key_72e1 = { 25 93 [2] 17 b1 [2] 11 84 [2] 3f 84 [2] 00 98 }

  condition:
    any of them
}