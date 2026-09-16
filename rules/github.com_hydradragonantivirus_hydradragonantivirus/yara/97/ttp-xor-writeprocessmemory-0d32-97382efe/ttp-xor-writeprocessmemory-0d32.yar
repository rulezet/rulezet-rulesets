rule TTP_XOR_WriteProcessMemory_0d32 {
  strings:
    $key_0d32 = { 5a 40 [2] 68 62 [2] 6e 57 [2] 40 57 [2] 7f 4b }

  condition:
    any of them
}