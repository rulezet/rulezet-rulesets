rule TTP_XOR_WriteProcessMemory_3413 {
  strings:
    $key_3413 = { 63 61 [2] 51 43 [2] 57 76 [2] 79 76 [2] 46 6a }

  condition:
    any of them
}