rule TTP_XOR_WriteProcessMemory_6131 {
  strings:
    $key_6131 = { 36 43 [2] 04 61 [2] 02 54 [2] 2c 54 [2] 13 48 }

  condition:
    any of them
}