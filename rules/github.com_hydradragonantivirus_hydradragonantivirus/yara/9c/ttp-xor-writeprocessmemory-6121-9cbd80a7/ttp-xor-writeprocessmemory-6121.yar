rule TTP_XOR_WriteProcessMemory_6121 {
  strings:
    $key_6121 = { 36 53 [2] 04 71 [2] 02 44 [2] 2c 44 [2] 13 58 }

  condition:
    any of them
}