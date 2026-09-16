rule TTP_XOR_WriteProcessMemory_4ce0 {
  strings:
    $key_4ce0 = { 1b 92 [2] 29 b0 [2] 2f 85 [2] 01 85 [2] 3e 99 }

  condition:
    any of them
}