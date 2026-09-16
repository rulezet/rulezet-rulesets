rule TTP_XOR_WriteProcessMemory_53d5 {
  strings:
    $key_53d5 = { 04 a7 [2] 36 85 [2] 30 b0 [2] 1e b0 [2] 21 ac }

  condition:
    any of them
}