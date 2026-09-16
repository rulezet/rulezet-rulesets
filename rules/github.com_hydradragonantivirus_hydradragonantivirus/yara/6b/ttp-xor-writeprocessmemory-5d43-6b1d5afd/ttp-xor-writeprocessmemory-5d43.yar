rule TTP_XOR_WriteProcessMemory_5d43 {
  strings:
    $key_5d43 = { 0a 31 [2] 38 13 [2] 3e 26 [2] 10 26 [2] 2f 3a }

  condition:
    any of them
}