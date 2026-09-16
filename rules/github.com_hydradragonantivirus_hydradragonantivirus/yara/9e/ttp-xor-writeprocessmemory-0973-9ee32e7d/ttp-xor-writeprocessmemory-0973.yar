rule TTP_XOR_WriteProcessMemory_0973 {
  strings:
    $key_0973 = { 5e 01 [2] 6c 23 [2] 6a 16 [2] 44 16 [2] 7b 0a }

  condition:
    any of them
}