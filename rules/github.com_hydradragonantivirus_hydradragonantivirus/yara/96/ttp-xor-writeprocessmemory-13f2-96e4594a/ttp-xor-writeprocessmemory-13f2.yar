rule TTP_XOR_WriteProcessMemory_13f2 {
  strings:
    $key_13f2 = { 44 80 [2] 76 a2 [2] 70 97 [2] 5e 97 [2] 61 8b }

  condition:
    any of them
}