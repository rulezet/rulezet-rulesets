rule TTP_XOR_WriteProcessMemory_7b13 {
  strings:
    $key_7b13 = { 2c 61 [2] 1e 43 [2] 18 76 [2] 36 76 [2] 09 6a }

  condition:
    any of them
}