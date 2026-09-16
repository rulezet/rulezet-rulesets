rule TTP_XOR_WriteProcessMemory_6163 {
  strings:
    $key_6163 = { 36 11 [2] 04 33 [2] 02 06 [2] 2c 06 [2] 13 1a }

  condition:
    any of them
}