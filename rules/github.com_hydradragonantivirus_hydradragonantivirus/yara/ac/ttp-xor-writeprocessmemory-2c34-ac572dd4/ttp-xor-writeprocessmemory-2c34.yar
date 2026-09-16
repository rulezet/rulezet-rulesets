rule TTP_XOR_WriteProcessMemory_2c34 {
  strings:
    $key_2c34 = { 7b 46 [2] 49 64 [2] 4f 51 [2] 61 51 [2] 5e 4d }

  condition:
    any of them
}