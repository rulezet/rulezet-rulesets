rule TTP_XOR_WriteProcessMemory_5603 {
  strings:
    $key_5603 = { 01 71 [2] 33 53 [2] 35 66 [2] 1b 66 [2] 24 7a }

  condition:
    any of them
}