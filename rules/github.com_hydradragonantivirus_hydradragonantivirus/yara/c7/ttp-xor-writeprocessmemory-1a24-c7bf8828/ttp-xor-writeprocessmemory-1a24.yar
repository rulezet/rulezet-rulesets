rule TTP_XOR_WriteProcessMemory_1a24 {
  strings:
    $key_1a24 = { 4d 56 [2] 7f 74 [2] 79 41 [2] 57 41 [2] 68 5d }

  condition:
    any of them
}