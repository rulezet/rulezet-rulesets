rule TTP_XOR_WriteProcessMemory_6122 {
  strings:
    $key_6122 = { 36 50 [2] 04 72 [2] 02 47 [2] 2c 47 [2] 13 5b }

  condition:
    any of them
}