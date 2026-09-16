rule TTP_XOR_WriteProcessMemory_2432 {
  strings:
    $key_2432 = { 73 40 [2] 41 62 [2] 47 57 [2] 69 57 [2] 56 4b }

  condition:
    any of them
}