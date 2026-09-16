rule TTP_XOR_WriteProcessMemory_1d36 {
  strings:
    $key_1d36 = { 4a 44 [2] 78 66 [2] 7e 53 [2] 50 53 [2] 6f 4f }

  condition:
    any of them
}