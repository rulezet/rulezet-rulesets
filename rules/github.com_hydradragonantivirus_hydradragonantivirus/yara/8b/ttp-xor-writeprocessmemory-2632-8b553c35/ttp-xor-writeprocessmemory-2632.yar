rule TTP_XOR_WriteProcessMemory_2632 {
  strings:
    $key_2632 = { 71 40 [2] 43 62 [2] 45 57 [2] 6b 57 [2] 54 4b }

  condition:
    any of them
}