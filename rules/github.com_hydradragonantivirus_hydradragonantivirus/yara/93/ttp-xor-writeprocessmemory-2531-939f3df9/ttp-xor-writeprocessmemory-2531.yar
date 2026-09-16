rule TTP_XOR_WriteProcessMemory_2531 {
  strings:
    $key_2531 = { 72 43 [2] 40 61 [2] 46 54 [2] 68 54 [2] 57 48 }

  condition:
    any of them
}