rule TTP_XOR_WriteProcessMemory_7c32 {
  strings:
    $key_7c32 = { 2b 40 [2] 19 62 [2] 1f 57 [2] 31 57 [2] 0e 4b }

  condition:
    any of them
}