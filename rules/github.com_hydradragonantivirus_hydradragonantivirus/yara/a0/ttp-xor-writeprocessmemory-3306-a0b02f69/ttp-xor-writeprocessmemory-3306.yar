rule TTP_XOR_WriteProcessMemory_3306 {
  strings:
    $key_3306 = { 64 74 [2] 56 56 [2] 50 63 [2] 7e 63 [2] 41 7f }

  condition:
    any of them
}