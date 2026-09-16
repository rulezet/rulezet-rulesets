rule TTP_XOR_WriteProcessMemory_1e32 {
  strings:
    $key_1e32 = { 49 40 [2] 7b 62 [2] 7d 57 [2] 53 57 [2] 6c 4b }

  condition:
    any of them
}