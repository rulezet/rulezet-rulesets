rule TTP_XOR_WriteProcessMemory_7513 {
  strings:
    $key_7513 = { 22 61 [2] 10 43 [2] 16 76 [2] 38 76 [2] 07 6a }

  condition:
    any of them
}