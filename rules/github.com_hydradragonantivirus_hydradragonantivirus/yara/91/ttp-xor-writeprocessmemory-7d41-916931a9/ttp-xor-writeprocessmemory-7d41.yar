rule TTP_XOR_WriteProcessMemory_7d41 {
  strings:
    $key_7d41 = { 2a 33 [2] 18 11 [2] 1e 24 [2] 30 24 [2] 0f 38 }

  condition:
    any of them
}