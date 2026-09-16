rule TTP_XOR_WriteProcessMemory_2c76 {
  strings:
    $key_2c76 = { 7b 04 [2] 49 26 [2] 4f 13 [2] 61 13 [2] 5e 0f }

  condition:
    any of them
}