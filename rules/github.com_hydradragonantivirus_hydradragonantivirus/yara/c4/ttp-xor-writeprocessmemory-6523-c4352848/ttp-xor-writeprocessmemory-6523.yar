rule TTP_XOR_WriteProcessMemory_6523 {
  strings:
    $key_6523 = { 32 51 [2] 00 73 [2] 06 46 [2] 28 46 [2] 17 5a }

  condition:
    any of them
}