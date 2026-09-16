rule TTP_XOR_WriteProcessMemory_1f40 {
  strings:
    $key_1f40 = { 48 32 [2] 7a 10 [2] 7c 25 [2] 52 25 [2] 6d 39 }

  condition:
    any of them
}