rule TTP_XOR_WriteProcessMemory_7d62 {
  strings:
    $key_7d62 = { 2a 10 [2] 18 32 [2] 1e 07 [2] 30 07 [2] 0f 1b }

  condition:
    any of them
}