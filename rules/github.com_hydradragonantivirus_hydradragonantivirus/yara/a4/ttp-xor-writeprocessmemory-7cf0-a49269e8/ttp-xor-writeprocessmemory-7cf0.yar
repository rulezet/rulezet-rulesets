rule TTP_XOR_WriteProcessMemory_7cf0 {
  strings:
    $key_7cf0 = { 2b 82 [2] 19 a0 [2] 1f 95 [2] 31 95 [2] 0e 89 }

  condition:
    any of them
}