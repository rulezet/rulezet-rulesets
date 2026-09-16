rule TTP_XOR_WriteProcessMemory_4c73 {
  strings:
    $key_4c73 = { 1b 01 [2] 29 23 [2] 2f 16 [2] 01 16 [2] 3e 0a }

  condition:
    any of them
}