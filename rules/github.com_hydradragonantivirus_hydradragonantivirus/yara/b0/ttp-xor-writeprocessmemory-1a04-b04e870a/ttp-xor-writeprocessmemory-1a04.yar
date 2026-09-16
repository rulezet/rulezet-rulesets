rule TTP_XOR_WriteProcessMemory_1a04 {
  strings:
    $key_1a04 = { 4d 76 [2] 7f 54 [2] 79 61 [2] 57 61 [2] 68 7d }

  condition:
    any of them
}