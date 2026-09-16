rule TTP_XOR_WriteProcessMemory_6192 {
  strings:
    $key_6192 = { 36 e0 [2] 04 c2 [2] 02 f7 [2] 2c f7 [2] 13 eb }

  condition:
    any of them
}