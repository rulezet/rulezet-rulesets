rule TTP_XOR_WriteProcessMemory_3760 {
  strings:
    $key_3760 = { 60 12 [2] 52 30 [2] 54 05 [2] 7a 05 [2] 45 19 }

  condition:
    any of them
}