rule TTP_XOR_WriteProcessMemory_2c53 {
  strings:
    $key_2c53 = { 7b 21 [2] 49 03 [2] 4f 36 [2] 61 36 [2] 5e 2a }

  condition:
    any of them
}