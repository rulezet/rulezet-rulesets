rule TTP_XOR_WriteProcessMemory_2d64 {
  strings:
    $key_2d64 = { 7a 16 [2] 48 34 [2] 4e 01 [2] 60 01 [2] 5f 1d }

  condition:
    any of them
}