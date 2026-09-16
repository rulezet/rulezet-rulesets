rule TTP_XOR_WriteProcessMemory_1333 {
  strings:
    $key_1333 = { 44 41 [2] 76 63 [2] 70 56 [2] 5e 56 [2] 61 4a }

  condition:
    any of them
}