rule TTP_XOR_WriteProcessMemory_7942 {
  strings:
    $key_7942 = { 2e 30 [2] 1c 12 [2] 1a 27 [2] 34 27 [2] 0b 3b }

  condition:
    any of them
}