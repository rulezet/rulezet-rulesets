rule TTP_XOR_WriteProcessMemory_5bd5 {
  strings:
    $key_5bd5 = { 0c a7 [2] 3e 85 [2] 38 b0 [2] 16 b0 [2] 29 ac }

  condition:
    any of them
}