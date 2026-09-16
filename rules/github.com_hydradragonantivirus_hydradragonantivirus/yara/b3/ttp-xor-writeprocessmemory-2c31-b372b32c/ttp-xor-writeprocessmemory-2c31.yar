rule TTP_XOR_WriteProcessMemory_2c31 {
  strings:
    $key_2c31 = { 7b 43 [2] 49 61 [2] 4f 54 [2] 61 54 [2] 5e 48 }

  condition:
    any of them
}