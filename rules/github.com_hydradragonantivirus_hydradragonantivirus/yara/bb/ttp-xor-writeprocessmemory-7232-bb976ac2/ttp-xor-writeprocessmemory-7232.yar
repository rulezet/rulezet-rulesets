rule TTP_XOR_WriteProcessMemory_7232 {
  strings:
    $key_7232 = { 25 40 [2] 17 62 [2] 11 57 [2] 3f 57 [2] 00 4b }

  condition:
    any of them
}