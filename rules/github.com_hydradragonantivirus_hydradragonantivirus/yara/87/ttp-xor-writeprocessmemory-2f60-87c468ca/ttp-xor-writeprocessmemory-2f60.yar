rule TTP_XOR_WriteProcessMemory_2f60 {
  strings:
    $key_2f60 = { 78 12 [2] 4a 30 [2] 4c 05 [2] 62 05 [2] 5d 19 }

  condition:
    any of them
}