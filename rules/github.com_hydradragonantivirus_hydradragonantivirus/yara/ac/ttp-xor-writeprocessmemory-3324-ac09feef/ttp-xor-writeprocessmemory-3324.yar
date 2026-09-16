rule TTP_XOR_WriteProcessMemory_3324 {
  strings:
    $key_3324 = { 64 56 [2] 56 74 [2] 50 41 [2] 7e 41 [2] 41 5d }

  condition:
    any of them
}