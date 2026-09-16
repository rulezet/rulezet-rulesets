rule TTP_XOR_WriteProcessMemory_2320 {
  strings:
    $key_2320 = { 74 52 [2] 46 70 [2] 40 45 [2] 6e 45 [2] 51 59 }

  condition:
    any of them
}