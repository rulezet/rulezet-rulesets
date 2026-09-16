rule TTP_XOR_WriteProcessMemory_62e4 {
  strings:
    $key_62e4 = { 35 96 [2] 07 b4 [2] 01 81 [2] 2f 81 [2] 10 9d }

  condition:
    any of them
}