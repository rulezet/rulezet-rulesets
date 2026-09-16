rule TTP_XOR_WriteProcessMemory_5c61 {
  strings:
    $key_5c61 = { 0b 13 [2] 39 31 [2] 3f 04 [2] 11 04 [2] 2e 18 }

  condition:
    any of them
}