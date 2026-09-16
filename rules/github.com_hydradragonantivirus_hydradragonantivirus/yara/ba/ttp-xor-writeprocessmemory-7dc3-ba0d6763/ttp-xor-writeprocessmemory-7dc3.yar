rule TTP_XOR_WriteProcessMemory_7dc3 {
  strings:
    $key_7dc3 = { 2a b1 [2] 18 93 [2] 1e a6 [2] 30 a6 [2] 0f ba }

  condition:
    any of them
}