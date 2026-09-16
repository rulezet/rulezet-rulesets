rule TTP_XOR_WriteProcessMemory_3504 {
  strings:
    $key_3504 = { 62 76 [2] 50 54 [2] 56 61 [2] 78 61 [2] 47 7d }

  condition:
    any of them
}