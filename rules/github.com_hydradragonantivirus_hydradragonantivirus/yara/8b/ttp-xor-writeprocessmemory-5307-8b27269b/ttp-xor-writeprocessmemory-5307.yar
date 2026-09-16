rule TTP_XOR_WriteProcessMemory_5307 {
  strings:
    $key_5307 = { 04 75 [2] 36 57 [2] 30 62 [2] 1e 62 [2] 21 7e }

  condition:
    any of them
}