rule TTP_XOR_WriteProcessMemory_7b33 {
  strings:
    $key_7b33 = { 2c 41 [2] 1e 63 [2] 18 56 [2] 36 56 [2] 09 4a }

  condition:
    any of them
}