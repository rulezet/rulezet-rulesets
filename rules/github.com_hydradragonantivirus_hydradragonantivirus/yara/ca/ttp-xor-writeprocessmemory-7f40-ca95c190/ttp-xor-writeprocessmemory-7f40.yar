rule TTP_XOR_WriteProcessMemory_7f40 {
  strings:
    $key_7f40 = { 28 32 [2] 1a 10 [2] 1c 25 [2] 32 25 [2] 0d 39 }

  condition:
    any of them
}