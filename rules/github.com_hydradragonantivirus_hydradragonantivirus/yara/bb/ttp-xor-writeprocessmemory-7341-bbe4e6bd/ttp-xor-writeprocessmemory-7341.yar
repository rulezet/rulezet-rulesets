rule TTP_XOR_WriteProcessMemory_7341 {
  strings:
    $key_7341 = { 24 33 [2] 16 11 [2] 10 24 [2] 3e 24 [2] 01 38 }

  condition:
    any of them
}