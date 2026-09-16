rule TTP_XOR_WriteProcessMemory_3622 {
  strings:
    $key_3622 = { 61 50 [2] 53 72 [2] 55 47 [2] 7b 47 [2] 44 5b }

  condition:
    any of them
}