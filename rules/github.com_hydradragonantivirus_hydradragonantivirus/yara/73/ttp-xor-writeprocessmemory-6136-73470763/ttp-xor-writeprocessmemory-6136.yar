rule TTP_XOR_WriteProcessMemory_6136 {
  strings:
    $key_6136 = { 36 44 [2] 04 66 [2] 02 53 [2] 2c 53 [2] 13 4f }

  condition:
    any of them
}