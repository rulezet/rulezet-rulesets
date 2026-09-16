rule TTP_XOR_WriteProcessMemory_5103 {
  strings:
    $key_5103 = { 06 71 [2] 34 53 [2] 32 66 [2] 1c 66 [2] 23 7a }

  condition:
    any of them
}