rule TTP_XOR_WriteProcessMemory_6303 {
  strings:
    $key_6303 = { 34 71 [2] 06 53 [2] 00 66 [2] 2e 66 [2] 11 7a }

  condition:
    any of them
}