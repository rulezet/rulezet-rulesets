rule TTP_XOR_WriteProcessMemory_1d33 {
  strings:
    $key_1d33 = { 4a 41 [2] 78 63 [2] 7e 56 [2] 50 56 [2] 6f 4a }

  condition:
    any of them
}