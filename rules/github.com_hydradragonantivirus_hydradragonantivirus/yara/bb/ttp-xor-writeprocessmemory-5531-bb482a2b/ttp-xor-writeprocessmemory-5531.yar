rule TTP_XOR_WriteProcessMemory_5531 {
  strings:
    $key_5531 = { 02 43 [2] 30 61 [2] 36 54 [2] 18 54 [2] 27 48 }

  condition:
    any of them
}