rule TTP_XOR_WriteProcessMemory_0741 {
  strings:
    $key_0741 = { 50 33 [2] 62 11 [2] 64 24 [2] 4a 24 [2] 75 38 }

  condition:
    any of them
}