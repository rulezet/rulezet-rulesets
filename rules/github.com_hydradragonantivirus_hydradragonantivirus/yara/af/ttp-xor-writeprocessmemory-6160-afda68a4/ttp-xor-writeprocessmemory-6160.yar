rule TTP_XOR_WriteProcessMemory_6160 {
  strings:
    $key_6160 = { 36 12 [2] 04 30 [2] 02 05 [2] 2c 05 [2] 13 19 }

  condition:
    any of them
}