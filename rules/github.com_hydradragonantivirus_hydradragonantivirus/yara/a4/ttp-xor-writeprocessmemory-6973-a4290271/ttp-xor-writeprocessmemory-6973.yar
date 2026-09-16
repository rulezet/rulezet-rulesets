rule TTP_XOR_WriteProcessMemory_6973 {
  strings:
    $key_6973 = { 3e 01 [2] 0c 23 [2] 0a 16 [2] 24 16 [2] 1b 0a }

  condition:
    any of them
}