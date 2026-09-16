rule TTP_XOR_WriteProcessMemory_6152 {
  strings:
    $key_6152 = { 36 20 [2] 04 02 [2] 02 37 [2] 2c 37 [2] 13 2b }

  condition:
    any of them
}