rule TTP_XOR_WriteProcessMemory_3261 {
  strings:
    $key_3261 = { 65 13 [2] 57 31 [2] 51 04 [2] 7f 04 [2] 40 18 }

  condition:
    any of them
}