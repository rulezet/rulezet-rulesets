rule TTP_XOR_WriteProcessMemory_7322 {
  strings:
    $key_7322 = { 24 50 [2] 16 72 [2] 10 47 [2] 3e 47 [2] 01 5b }

  condition:
    any of them
}