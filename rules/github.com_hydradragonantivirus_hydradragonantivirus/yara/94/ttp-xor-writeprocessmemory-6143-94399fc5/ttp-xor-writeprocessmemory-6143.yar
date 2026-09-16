rule TTP_XOR_WriteProcessMemory_6143 {
  strings:
    $key_6143 = { 36 31 [2] 04 13 [2] 02 26 [2] 2c 26 [2] 13 3a }

  condition:
    any of them
}