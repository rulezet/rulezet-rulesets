rule TTP_XOR_WriteProcessMemory_0ce0 {
  strings:
    $key_0ce0 = { 5b 92 [2] 69 b0 [2] 6f 85 [2] 41 85 [2] 7e 99 }

  condition:
    any of them
}