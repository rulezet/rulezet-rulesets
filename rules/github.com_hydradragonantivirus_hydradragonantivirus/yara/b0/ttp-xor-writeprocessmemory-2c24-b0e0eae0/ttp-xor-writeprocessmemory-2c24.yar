rule TTP_XOR_WriteProcessMemory_2c24 {
  strings:
    $key_2c24 = { 7b 56 [2] 49 74 [2] 4f 41 [2] 61 41 [2] 5e 5d }

  condition:
    any of them
}