rule TTP_XOR_WriteProcessMemory_5d64 {
  strings:
    $key_5d64 = { 0a 16 [2] 38 34 [2] 3e 01 [2] 10 01 [2] 2f 1d }

  condition:
    any of them
}