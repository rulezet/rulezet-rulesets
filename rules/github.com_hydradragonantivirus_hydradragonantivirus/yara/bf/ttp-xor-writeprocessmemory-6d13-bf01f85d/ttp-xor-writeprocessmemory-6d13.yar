rule TTP_XOR_WriteProcessMemory_6d13 {
  strings:
    $key_6d13 = { 3a 61 [2] 08 43 [2] 0e 76 [2] 20 76 [2] 1f 6a }

  condition:
    any of them
}