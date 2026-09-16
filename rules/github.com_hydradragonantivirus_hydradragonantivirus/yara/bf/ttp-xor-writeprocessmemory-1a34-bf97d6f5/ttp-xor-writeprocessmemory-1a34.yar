rule TTP_XOR_WriteProcessMemory_1a34 {
  strings:
    $key_1a34 = { 4d 46 [2] 7f 64 [2] 79 51 [2] 57 51 [2] 68 4d }

  condition:
    any of them
}