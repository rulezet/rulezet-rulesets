rule TTP_XOR_WriteProcessMemory_7d60 {
  strings:
    $key_7d60 = { 2a 12 [2] 18 30 [2] 1e 05 [2] 30 05 [2] 0f 19 }

  condition:
    any of them
}