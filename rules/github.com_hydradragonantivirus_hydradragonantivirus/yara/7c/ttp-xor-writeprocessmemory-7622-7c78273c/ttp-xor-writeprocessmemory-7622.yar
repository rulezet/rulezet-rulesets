rule TTP_XOR_WriteProcessMemory_7622 {
  strings:
    $key_7622 = { 21 50 [2] 13 72 [2] 15 47 [2] 3b 47 [2] 04 5b }

  condition:
    any of them
}