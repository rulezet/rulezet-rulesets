rule TTP_XOR_WriteProcessMemory_7262 {
  strings:
    $key_7262 = { 25 10 [2] 17 32 [2] 11 07 [2] 3f 07 [2] 00 1b }

  condition:
    any of them
}