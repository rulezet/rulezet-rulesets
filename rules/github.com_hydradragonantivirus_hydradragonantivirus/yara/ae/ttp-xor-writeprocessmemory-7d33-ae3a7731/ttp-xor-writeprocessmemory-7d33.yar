rule TTP_XOR_WriteProcessMemory_7d33 {
  strings:
    $key_7d33 = { 2a 41 [2] 18 63 [2] 1e 56 [2] 30 56 [2] 0f 4a }

  condition:
    any of them
}