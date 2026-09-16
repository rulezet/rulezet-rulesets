rule TTP_XOR_WriteProcessMemory_7473 {
  strings:
    $key_7473 = { 23 01 [2] 11 23 [2] 17 16 [2] 39 16 [2] 06 0a }

  condition:
    any of them
}