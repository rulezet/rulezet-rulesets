rule TTP_XOR_WriteProcessMemory_7c43 {
  strings:
    $key_7c43 = { 2b 31 [2] 19 13 [2] 1f 26 [2] 31 26 [2] 0e 3a }

  condition:
    any of them
}