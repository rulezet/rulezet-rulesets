rule TTP_XOR_WriteProcessMemory_5113 {
  strings:
    $key_5113 = { 06 61 [2] 34 43 [2] 32 76 [2] 1c 76 [2] 23 6a }

  condition:
    any of them
}