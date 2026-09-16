rule TTP_XOR_WriteProcessMemory_4524 {
  strings:
    $key_4524 = { 12 56 [2] 20 74 [2] 26 41 [2] 08 41 [2] 37 5d }

  condition:
    any of them
}