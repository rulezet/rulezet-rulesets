rule TTP_XOR_WriteProcessMemory_3531 {
  strings:
    $key_3531 = { 62 43 [2] 50 61 [2] 56 54 [2] 78 54 [2] 47 48 }

  condition:
    any of them
}