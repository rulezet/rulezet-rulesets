rule TTP_XOR_WriteProcessMemory_6104 {
  strings:
    $key_6104 = { 36 76 [2] 04 54 [2] 02 61 [2] 2c 61 [2] 13 7d }

  condition:
    any of them
}