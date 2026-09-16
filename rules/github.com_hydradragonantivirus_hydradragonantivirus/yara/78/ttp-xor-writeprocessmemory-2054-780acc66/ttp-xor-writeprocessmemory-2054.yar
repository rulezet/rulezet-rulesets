rule TTP_XOR_WriteProcessMemory_2054 {
  strings:
    $key_2054 = { 77 26 [2] 45 04 [2] 43 31 [2] 6d 31 [2] 52 2d }

  condition:
    any of them
}