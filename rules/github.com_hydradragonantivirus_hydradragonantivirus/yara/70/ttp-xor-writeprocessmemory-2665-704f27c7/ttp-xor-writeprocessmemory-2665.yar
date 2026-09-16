rule TTP_XOR_WriteProcessMemory_2665 {
  strings:
    $key_2665 = { 71 17 [2] 43 35 [2] 45 00 [2] 6b 00 [2] 54 1c }

  condition:
    any of them
}