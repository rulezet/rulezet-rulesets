rule TTP_XOR_WriteProcessMemory_5304 {
  strings:
    $key_5304 = { 04 76 [2] 36 54 [2] 30 61 [2] 1e 61 [2] 21 7d }

  condition:
    any of them
}