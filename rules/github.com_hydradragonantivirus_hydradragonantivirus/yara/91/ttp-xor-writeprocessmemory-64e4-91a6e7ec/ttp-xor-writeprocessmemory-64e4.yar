rule TTP_XOR_WriteProcessMemory_64e4 {
  strings:
    $key_64e4 = { 33 96 [2] 01 b4 [2] 07 81 [2] 29 81 [2] 16 9d }

  condition:
    any of them
}