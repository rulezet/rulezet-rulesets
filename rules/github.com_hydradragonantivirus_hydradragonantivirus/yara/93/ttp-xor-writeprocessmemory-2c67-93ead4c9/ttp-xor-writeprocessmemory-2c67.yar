rule TTP_XOR_WriteProcessMemory_2c67 {
  strings:
    $key_2c67 = { 7b 15 [2] 49 37 [2] 4f 02 [2] 61 02 [2] 5e 1e }

  condition:
    any of them
}