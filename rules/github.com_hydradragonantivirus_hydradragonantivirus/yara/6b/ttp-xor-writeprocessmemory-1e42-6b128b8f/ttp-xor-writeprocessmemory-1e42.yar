rule TTP_XOR_WriteProcessMemory_1e42 {
  strings:
    $key_1e42 = { 49 30 [2] 7b 12 [2] 7d 27 [2] 53 27 [2] 6c 3b }

  condition:
    any of them
}