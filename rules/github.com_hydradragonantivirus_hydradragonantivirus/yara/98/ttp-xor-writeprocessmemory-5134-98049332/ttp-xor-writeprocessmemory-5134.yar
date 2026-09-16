rule TTP_XOR_WriteProcessMemory_5134 {
  strings:
    $key_5134 = { 06 46 [2] 34 64 [2] 32 51 [2] 1c 51 [2] 23 4d }

  condition:
    any of them
}