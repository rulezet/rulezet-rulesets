rule TTP_XOR_WriteProcessMemory_4260 {
  strings:
    $key_4260 = { 15 12 [2] 27 30 [2] 21 05 [2] 0f 05 [2] 30 19 }

  condition:
    any of them
}