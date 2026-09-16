rule TTP_XOR_WriteProcessMemory_6161 {
  strings:
    $key_6161 = { 36 13 [2] 04 31 [2] 02 04 [2] 2c 04 [2] 13 18 }

  condition:
    any of them
}