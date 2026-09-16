rule TTP_XOR_WriteProcessMemory_7470 {
  strings:
    $key_7470 = { 23 02 [2] 11 20 [2] 17 15 [2] 39 15 [2] 06 09 }

  condition:
    any of them
}