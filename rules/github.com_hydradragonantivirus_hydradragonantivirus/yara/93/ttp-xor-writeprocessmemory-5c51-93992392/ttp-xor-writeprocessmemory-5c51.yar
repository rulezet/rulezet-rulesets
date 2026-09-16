rule TTP_XOR_WriteProcessMemory_5c51 {
  strings:
    $key_5c51 = { 0b 23 [2] 39 01 [2] 3f 34 [2] 11 34 [2] 2e 28 }

  condition:
    any of them
}