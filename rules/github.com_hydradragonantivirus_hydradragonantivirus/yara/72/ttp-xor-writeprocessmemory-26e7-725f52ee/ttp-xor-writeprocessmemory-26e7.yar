rule TTP_XOR_WriteProcessMemory_26e7 {
  strings:
    $key_26e7 = { 71 95 [2] 43 b7 [2] 45 82 [2] 6b 82 [2] 54 9e }

  condition:
    any of them
}