rule TTP_XOR_WriteProcessMemory_6102 {
  strings:
    $key_6102 = { 36 70 [2] 04 52 [2] 02 67 [2] 2c 67 [2] 13 7b }

  condition:
    any of them
}