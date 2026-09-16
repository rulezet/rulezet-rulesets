rule TTP_XOR_WriteProcessMemory_2371 {
  strings:
    $key_2371 = { 74 03 [2] 46 21 [2] 40 14 [2] 6e 14 [2] 51 08 }

  condition:
    any of them
}