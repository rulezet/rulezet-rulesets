rule TTP_XOR_WriteProcessMemory_7361 {
  strings:
    $key_7361 = { 24 13 [2] 16 31 [2] 10 04 [2] 3e 04 [2] 01 18 }

  condition:
    any of them
}