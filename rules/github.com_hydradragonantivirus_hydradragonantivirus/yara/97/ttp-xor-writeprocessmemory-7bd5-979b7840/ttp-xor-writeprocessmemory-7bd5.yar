rule TTP_XOR_WriteProcessMemory_7bd5 {
  strings:
    $key_7bd5 = { 2c a7 [2] 1e 85 [2] 18 b0 [2] 36 b0 [2] 09 ac }

  condition:
    any of them
}