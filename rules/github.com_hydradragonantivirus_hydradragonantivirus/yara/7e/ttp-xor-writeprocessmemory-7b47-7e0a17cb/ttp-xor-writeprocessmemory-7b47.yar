rule TTP_XOR_WriteProcessMemory_7b47 {
  strings:
    $key_7b47 = { 2c 35 [2] 1e 17 [2] 18 22 [2] 36 22 [2] 09 3e }

  condition:
    any of them
}