rule TTP_XOR_WriteProcessMemory_4a50 {
  strings:
    $key_4a50 = { 1d 22 [2] 2f 00 [2] 29 35 [2] 07 35 [2] 38 29 }

  condition:
    any of them
}