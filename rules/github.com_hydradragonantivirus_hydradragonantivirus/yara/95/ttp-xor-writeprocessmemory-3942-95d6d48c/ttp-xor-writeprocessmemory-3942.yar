rule TTP_XOR_WriteProcessMemory_3942 {
  strings:
    $key_3942 = { 6e 30 [2] 5c 12 [2] 5a 27 [2] 74 27 [2] 4b 3b }

  condition:
    any of them
}