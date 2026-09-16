rule TTP_XOR_WriteProcessMemory_2ba7 {
  strings:
    $key_2ba7 = { 7c d5 [2] 4e f7 [2] 48 c2 [2] 66 c2 [2] 59 de }

  condition:
    any of them
}