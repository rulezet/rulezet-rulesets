rule TTP_XOR_WriteProcessMemory_7cf1 {
  strings:
    $key_7cf1 = { 2b 83 [2] 19 a1 [2] 1f 94 [2] 31 94 [2] 0e 88 }

  condition:
    any of them
}