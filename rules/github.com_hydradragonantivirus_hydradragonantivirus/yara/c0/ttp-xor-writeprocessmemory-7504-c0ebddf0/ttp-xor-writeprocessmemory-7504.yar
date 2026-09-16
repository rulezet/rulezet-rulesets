rule TTP_XOR_WriteProcessMemory_7504 {
  strings:
    $key_7504 = { 22 76 [2] 10 54 [2] 16 61 [2] 38 61 [2] 07 7d }

  condition:
    any of them
}