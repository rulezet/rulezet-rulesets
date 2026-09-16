rule TTP_XOR_WriteProcessMemory_1777 {
  strings:
    $key_1777 = { 40 05 [2] 72 27 [2] 74 12 [2] 5a 12 [2] 65 0e }

  condition:
    any of them
}