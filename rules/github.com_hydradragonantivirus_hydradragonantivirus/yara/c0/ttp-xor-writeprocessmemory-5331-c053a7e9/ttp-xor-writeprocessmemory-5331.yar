rule TTP_XOR_WriteProcessMemory_5331 {
  strings:
    $key_5331 = { 04 43 [2] 36 61 [2] 30 54 [2] 1e 54 [2] 21 48 }

  condition:
    any of them
}