rule TTP_XOR_WriteProcessMemory_7b02 {
  strings:
    $key_7b02 = { 2c 70 [2] 1e 52 [2] 18 67 [2] 36 67 [2] 09 7b }

  condition:
    any of them
}