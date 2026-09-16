rule TTP_XOR_WriteProcessMemory_6134 {
  strings:
    $key_6134 = { 36 46 [2] 04 64 [2] 02 51 [2] 2c 51 [2] 13 4d }

  condition:
    any of them
}