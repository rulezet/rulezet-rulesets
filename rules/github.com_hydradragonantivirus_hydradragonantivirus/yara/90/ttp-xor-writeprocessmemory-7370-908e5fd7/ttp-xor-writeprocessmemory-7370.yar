rule TTP_XOR_WriteProcessMemory_7370 {
  strings:
    $key_7370 = { 24 02 [2] 16 20 [2] 10 15 [2] 3e 15 [2] 01 09 }

  condition:
    any of them
}