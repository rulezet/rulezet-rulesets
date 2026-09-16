rule TTP_XOR_WriteProcessMemory_5734 {
  strings:
    $key_5734 = { 00 46 [2] 32 64 [2] 34 51 [2] 1a 51 [2] 25 4d }

  condition:
    any of them
}