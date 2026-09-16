rule TTP_XOR_WriteProcessMemory_6236 {
  strings:
    $key_6236 = { 35 44 [2] 07 66 [2] 01 53 [2] 2f 53 [2] 10 4f }

  condition:
    any of them
}