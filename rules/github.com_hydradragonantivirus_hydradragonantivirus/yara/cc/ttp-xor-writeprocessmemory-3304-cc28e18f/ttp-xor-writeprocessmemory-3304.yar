rule TTP_XOR_WriteProcessMemory_3304 {
  strings:
    $key_3304 = { 64 76 [2] 56 54 [2] 50 61 [2] 7e 61 [2] 41 7d }

  condition:
    any of them
}