rule TTP_XOR_WriteProcessMemory_7821 {
  strings:
    $key_7821 = { 2f 53 [2] 1d 71 [2] 1b 44 [2] 35 44 [2] 0a 58 }

  condition:
    any of them
}