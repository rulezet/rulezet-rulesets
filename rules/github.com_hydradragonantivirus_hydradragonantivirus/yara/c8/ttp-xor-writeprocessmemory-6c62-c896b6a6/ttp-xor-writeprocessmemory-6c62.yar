rule TTP_XOR_WriteProcessMemory_6c62 {
  strings:
    $key_6c62 = { 3b 10 [2] 09 32 [2] 0f 07 [2] 21 07 [2] 1e 1b }

  condition:
    any of them
}