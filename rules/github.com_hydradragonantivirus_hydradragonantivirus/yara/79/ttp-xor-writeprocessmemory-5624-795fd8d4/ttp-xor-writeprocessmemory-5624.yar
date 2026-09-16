rule TTP_XOR_WriteProcessMemory_5624 {
  strings:
    $key_5624 = { 01 56 [2] 33 74 [2] 35 41 [2] 1b 41 [2] 24 5d }

  condition:
    any of them
}