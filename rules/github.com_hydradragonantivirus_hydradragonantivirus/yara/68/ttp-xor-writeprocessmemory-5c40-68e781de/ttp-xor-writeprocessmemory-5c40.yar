rule TTP_XOR_WriteProcessMemory_5c40 {
  strings:
    $key_5c40 = { 0b 32 [2] 39 10 [2] 3f 25 [2] 11 25 [2] 2e 39 }

  condition:
    any of them
}