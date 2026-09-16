rule TTP_XOR_WriteProcessMemory_62e7 {
  strings:
    $key_62e7 = { 35 95 [2] 07 b7 [2] 01 82 [2] 2f 82 [2] 10 9e }

  condition:
    any of them
}