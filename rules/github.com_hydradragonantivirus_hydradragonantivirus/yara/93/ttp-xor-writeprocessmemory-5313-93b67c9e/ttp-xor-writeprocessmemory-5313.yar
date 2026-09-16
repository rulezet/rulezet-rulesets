rule TTP_XOR_WriteProcessMemory_5313 {
  strings:
    $key_5313 = { 04 61 [2] 36 43 [2] 30 76 [2] 1e 76 [2] 21 6a }

  condition:
    any of them
}