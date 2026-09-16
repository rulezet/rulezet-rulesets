rule TTP_XOR_WriteProcessMemory_6182 {
  strings:
    $key_6182 = { 36 f0 [2] 04 d2 [2] 02 e7 [2] 2c e7 [2] 13 fb }

  condition:
    any of them
}