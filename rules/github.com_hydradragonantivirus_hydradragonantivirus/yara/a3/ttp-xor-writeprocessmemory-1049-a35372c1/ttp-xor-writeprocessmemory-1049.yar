rule TTP_XOR_WriteProcessMemory_1049 {
  strings:
    $key_1049 = { 47 3b [2] 75 19 [2] 73 2c [2] 5d 2c [2] 62 30 }

  condition:
    any of them
}