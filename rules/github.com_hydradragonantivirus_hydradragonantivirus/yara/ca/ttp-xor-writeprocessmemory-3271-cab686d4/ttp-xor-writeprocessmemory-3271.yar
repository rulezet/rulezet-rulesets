rule TTP_XOR_WriteProcessMemory_3271 {
  strings:
    $key_3271 = { 65 03 [2] 57 21 [2] 51 14 [2] 7f 14 [2] 40 08 }

  condition:
    any of them
}