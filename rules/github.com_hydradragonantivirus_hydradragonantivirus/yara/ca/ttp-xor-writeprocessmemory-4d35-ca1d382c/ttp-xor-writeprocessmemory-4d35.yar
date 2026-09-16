rule TTP_XOR_WriteProcessMemory_4d35 {
  strings:
    $key_4d35 = { 1a 47 [2] 28 65 [2] 2e 50 [2] 00 50 [2] 3f 4c }

  condition:
    any of them
}