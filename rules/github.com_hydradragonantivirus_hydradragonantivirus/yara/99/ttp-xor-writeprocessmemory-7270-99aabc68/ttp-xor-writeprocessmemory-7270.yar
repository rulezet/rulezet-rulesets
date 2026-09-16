rule TTP_XOR_WriteProcessMemory_7270 {
  strings:
    $key_7270 = { 25 02 [2] 17 20 [2] 11 15 [2] 3f 15 [2] 00 09 }

  condition:
    any of them
}