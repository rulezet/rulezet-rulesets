rule TTP_XOR_WriteProcessMemory_6174 {
  strings:
    $key_6174 = { 36 06 [2] 04 24 [2] 02 11 [2] 2c 11 [2] 13 0d }

  condition:
    any of them
}