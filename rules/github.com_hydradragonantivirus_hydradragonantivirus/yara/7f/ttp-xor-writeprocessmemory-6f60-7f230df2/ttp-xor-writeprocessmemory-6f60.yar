rule TTP_XOR_WriteProcessMemory_6f60 {
  strings:
    $key_6f60 = { 38 12 [2] 0a 30 [2] 0c 05 [2] 22 05 [2] 1d 19 }

  condition:
    any of them
}