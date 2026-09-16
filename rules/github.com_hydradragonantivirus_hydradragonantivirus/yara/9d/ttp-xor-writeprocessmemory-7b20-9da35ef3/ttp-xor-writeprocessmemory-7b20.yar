rule TTP_XOR_WriteProcessMemory_7b20 {
  strings:
    $key_7b20 = { 2c 52 [2] 1e 70 [2] 18 45 [2] 36 45 [2] 09 59 }

  condition:
    any of them
}