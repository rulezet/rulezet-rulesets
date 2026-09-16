rule TTP_XOR_WriteProcessMemory_1e40 {
  strings:
    $key_1e40 = { 49 32 [2] 7b 10 [2] 7d 25 [2] 53 25 [2] 6c 39 }

  condition:
    any of them
}