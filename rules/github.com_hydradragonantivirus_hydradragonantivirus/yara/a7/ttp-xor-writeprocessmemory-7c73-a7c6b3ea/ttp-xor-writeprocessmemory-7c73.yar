rule TTP_XOR_WriteProcessMemory_7c73 {
  strings:
    $key_7c73 = { 2b 01 [2] 19 23 [2] 1f 16 [2] 31 16 [2] 0e 0a }

  condition:
    any of them
}