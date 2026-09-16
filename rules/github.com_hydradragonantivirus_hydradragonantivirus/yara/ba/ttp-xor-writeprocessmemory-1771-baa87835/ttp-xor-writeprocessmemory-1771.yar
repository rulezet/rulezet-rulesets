rule TTP_XOR_WriteProcessMemory_1771 {
  strings:
    $key_1771 = { 40 03 [2] 72 21 [2] 74 14 [2] 5a 14 [2] 65 08 }

  condition:
    any of them
}