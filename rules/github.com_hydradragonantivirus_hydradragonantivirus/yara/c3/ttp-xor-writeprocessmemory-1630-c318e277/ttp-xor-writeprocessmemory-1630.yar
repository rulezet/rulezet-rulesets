rule TTP_XOR_WriteProcessMemory_1630 {
  strings:
    $key_1630 = { 41 42 [2] 73 60 [2] 75 55 [2] 5b 55 [2] 64 49 }

  condition:
    any of them
}