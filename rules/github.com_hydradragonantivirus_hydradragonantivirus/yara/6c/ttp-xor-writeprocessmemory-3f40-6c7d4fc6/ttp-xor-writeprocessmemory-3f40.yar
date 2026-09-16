rule TTP_XOR_WriteProcessMemory_3f40 {
  strings:
    $key_3f40 = { 68 32 [2] 5a 10 [2] 5c 25 [2] 72 25 [2] 4d 39 }

  condition:
    any of them
}