rule TTP_XOR_WriteProcessMemory_5a50 {
  strings:
    $key_5a50 = { 0d 22 [2] 3f 00 [2] 39 35 [2] 17 35 [2] 28 29 }

  condition:
    any of them
}