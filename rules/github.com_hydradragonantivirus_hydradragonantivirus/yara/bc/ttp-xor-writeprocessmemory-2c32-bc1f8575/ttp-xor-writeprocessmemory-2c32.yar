rule TTP_XOR_WriteProcessMemory_2c32 {
  strings:
    $key_2c32 = { 7b 40 [2] 49 62 [2] 4f 57 [2] 61 57 [2] 5e 4b }

  condition:
    any of them
}