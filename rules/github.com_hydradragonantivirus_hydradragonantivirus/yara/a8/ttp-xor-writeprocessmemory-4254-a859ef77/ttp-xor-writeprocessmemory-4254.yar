rule TTP_XOR_WriteProcessMemory_4254 {
  strings:
    $key_4254 = { 15 26 [2] 27 04 [2] 21 31 [2] 0f 31 [2] 30 2d }

  condition:
    any of them
}