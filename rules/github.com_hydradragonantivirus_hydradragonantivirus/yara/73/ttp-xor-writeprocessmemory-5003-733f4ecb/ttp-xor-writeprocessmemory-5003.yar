rule TTP_XOR_WriteProcessMemory_5003 {
  strings:
    $key_5003 = { 07 71 [2] 35 53 [2] 33 66 [2] 1d 66 [2] 22 7a }

  condition:
    any of them
}