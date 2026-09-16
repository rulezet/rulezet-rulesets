rule TTP_XOR_WriteProcessMemory_1070 {
  strings:
    $key_1070 = { 47 02 [2] 75 20 [2] 73 15 [2] 5d 15 [2] 62 09 }

  condition:
    any of them
}