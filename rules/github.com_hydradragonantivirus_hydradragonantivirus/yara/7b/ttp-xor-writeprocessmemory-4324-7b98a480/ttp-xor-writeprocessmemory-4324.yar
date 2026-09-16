rule TTP_XOR_WriteProcessMemory_4324 {
  strings:
    $key_4324 = { 14 56 [2] 26 74 [2] 20 41 [2] 0e 41 [2] 31 5d }

  condition:
    any of them
}