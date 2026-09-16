rule TTP_XOR_WriteProcessMemory_1760 {
  strings:
    $key_1760 = { 40 12 [2] 72 30 [2] 74 05 [2] 5a 05 [2] 65 19 }

  condition:
    any of them
}