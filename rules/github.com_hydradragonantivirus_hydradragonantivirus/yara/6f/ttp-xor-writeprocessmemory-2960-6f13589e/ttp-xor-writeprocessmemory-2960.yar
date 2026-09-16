rule TTP_XOR_WriteProcessMemory_2960 {
  strings:
    $key_2960 = { 7e 12 [2] 4c 30 [2] 4a 05 [2] 64 05 [2] 5b 19 }

  condition:
    any of them
}