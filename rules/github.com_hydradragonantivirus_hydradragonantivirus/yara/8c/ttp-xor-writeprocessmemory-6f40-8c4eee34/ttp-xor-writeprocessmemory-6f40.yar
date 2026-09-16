rule TTP_XOR_WriteProcessMemory_6f40 {
  strings:
    $key_6f40 = { 38 32 [2] 0a 10 [2] 0c 25 [2] 22 25 [2] 1d 39 }

  condition:
    any of them
}