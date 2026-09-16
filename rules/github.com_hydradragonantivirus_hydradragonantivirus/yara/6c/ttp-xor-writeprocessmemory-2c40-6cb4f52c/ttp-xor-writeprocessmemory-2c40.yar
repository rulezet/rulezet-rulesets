rule TTP_XOR_WriteProcessMemory_2c40 {
  strings:
    $key_2c40 = { 7b 32 [2] 49 10 [2] 4f 25 [2] 61 25 [2] 5e 39 }

  condition:
    any of them
}