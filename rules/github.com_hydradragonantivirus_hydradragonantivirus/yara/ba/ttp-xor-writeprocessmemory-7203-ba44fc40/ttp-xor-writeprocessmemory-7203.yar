rule TTP_XOR_WriteProcessMemory_7203 {
  strings:
    $key_7203 = { 25 71 [2] 17 53 [2] 11 66 [2] 3f 66 [2] 00 7a }

  condition:
    any of them
}