rule TTP_XOR_WriteProcessMemory_72e4 {
  strings:
    $key_72e4 = { 25 96 [2] 17 b4 [2] 11 81 [2] 3f 81 [2] 00 9d }

  condition:
    any of them
}