rule TTP_XOR_WriteProcessMemory_1940 {
  strings:
    $key_1940 = { 4e 32 [2] 7c 10 [2] 7a 25 [2] 54 25 [2] 6b 39 }

  condition:
    any of them
}