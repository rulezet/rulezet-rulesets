rule TTP_XOR_WriteProcessMemory_7233 {
  strings:
    $key_7233 = { 25 41 [2] 17 63 [2] 11 56 [2] 3f 56 [2] 00 4a }

  condition:
    any of them
}