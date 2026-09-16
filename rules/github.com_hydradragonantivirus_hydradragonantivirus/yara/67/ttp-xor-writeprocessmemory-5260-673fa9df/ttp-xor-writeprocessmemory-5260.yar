rule TTP_XOR_WriteProcessMemory_5260 {
  strings:
    $key_5260 = { 05 12 [2] 37 30 [2] 31 05 [2] 1f 05 [2] 20 19 }

  condition:
    any of them
}