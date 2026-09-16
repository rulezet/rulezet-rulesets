rule TTP_XOR_WriteProcessMemory_6154 {
  strings:
    $key_6154 = { 36 26 [2] 04 04 [2] 02 31 [2] 2c 31 [2] 13 2d }

  condition:
    any of them
}