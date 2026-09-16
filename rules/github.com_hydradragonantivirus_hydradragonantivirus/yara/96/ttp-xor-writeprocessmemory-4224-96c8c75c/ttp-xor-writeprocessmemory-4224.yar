rule TTP_XOR_WriteProcessMemory_4224 {
  strings:
    $key_4224 = { 15 56 [2] 27 74 [2] 21 41 [2] 0f 41 [2] 30 5d }

  condition:
    any of them
}