rule TTP_XOR_WriteProcessMemory_5311 {
  strings:
    $key_5311 = { 04 63 [2] 36 41 [2] 30 74 [2] 1e 74 [2] 21 68 }

  condition:
    any of them
}