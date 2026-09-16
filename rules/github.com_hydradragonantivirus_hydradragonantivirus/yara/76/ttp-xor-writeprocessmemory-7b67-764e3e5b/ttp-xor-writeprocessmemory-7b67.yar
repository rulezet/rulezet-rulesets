rule TTP_XOR_WriteProcessMemory_7b67 {
  strings:
    $key_7b67 = { 2c 15 [2] 1e 37 [2] 18 02 [2] 36 02 [2] 09 1e }

  condition:
    any of them
}