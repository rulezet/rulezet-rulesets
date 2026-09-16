rule TTP_XOR_WriteProcessMemory_3172 {
  strings:
    $key_3172 = { 66 00 [2] 54 22 [2] 52 17 [2] 7c 17 [2] 43 0b }

  condition:
    any of them
}