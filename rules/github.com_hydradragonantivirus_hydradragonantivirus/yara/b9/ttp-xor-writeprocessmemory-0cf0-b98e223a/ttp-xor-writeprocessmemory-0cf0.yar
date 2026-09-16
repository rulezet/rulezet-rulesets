rule TTP_XOR_WriteProcessMemory_0cf0 {
  strings:
    $key_0cf0 = { 5b 82 [2] 69 a0 [2] 6f 95 [2] 41 95 [2] 7e 89 }

  condition:
    any of them
}