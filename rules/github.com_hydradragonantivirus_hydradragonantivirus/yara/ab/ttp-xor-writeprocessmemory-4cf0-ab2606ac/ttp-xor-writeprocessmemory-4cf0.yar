rule TTP_XOR_WriteProcessMemory_4cf0 {
  strings:
    $key_4cf0 = { 1b 82 [2] 29 a0 [2] 2f 95 [2] 01 95 [2] 3e 89 }

  condition:
    any of them
}