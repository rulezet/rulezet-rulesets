rule TTP_XOR_WriteProcessMemory_4d34 {
  strings:
    $key_4d34 = { 1a 46 [2] 28 64 [2] 2e 51 [2] 00 51 [2] 3f 4d }

  condition:
    any of them
}