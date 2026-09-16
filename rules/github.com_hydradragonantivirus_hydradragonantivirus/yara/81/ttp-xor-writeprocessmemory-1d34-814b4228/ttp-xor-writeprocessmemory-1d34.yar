rule TTP_XOR_WriteProcessMemory_1d34 {
  strings:
    $key_1d34 = { 4a 46 [2] 78 64 [2] 7e 51 [2] 50 51 [2] 6f 4d }

  condition:
    any of them
}