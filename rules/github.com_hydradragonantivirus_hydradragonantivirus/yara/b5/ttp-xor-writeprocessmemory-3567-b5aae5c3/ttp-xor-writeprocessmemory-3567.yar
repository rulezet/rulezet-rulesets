rule TTP_XOR_WriteProcessMemory_3567 {
  strings:
    $key_3567 = { 62 15 [2] 50 37 [2] 56 02 [2] 78 02 [2] 47 1e }

  condition:
    any of them
}