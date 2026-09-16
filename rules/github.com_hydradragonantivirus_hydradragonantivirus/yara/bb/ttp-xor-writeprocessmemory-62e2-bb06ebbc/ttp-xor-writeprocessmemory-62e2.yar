rule TTP_XOR_WriteProcessMemory_62e2 {
  strings:
    $key_62e2 = { 35 90 [2] 07 b2 [2] 01 87 [2] 2f 87 [2] 10 9b }

  condition:
    any of them
}