rule TTP_XOR_WriteProcessMemory_1f60 {
  strings:
    $key_1f60 = { 48 12 [2] 7a 30 [2] 7c 05 [2] 52 05 [2] 6d 19 }

  condition:
    any of them
}