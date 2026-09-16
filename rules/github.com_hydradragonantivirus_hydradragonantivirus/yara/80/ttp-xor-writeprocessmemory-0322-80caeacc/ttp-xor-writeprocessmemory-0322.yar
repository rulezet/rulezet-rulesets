rule TTP_XOR_WriteProcessMemory_0322 {
  strings:
    $key_0322 = { 54 50 [2] 66 72 [2] 60 47 [2] 4e 47 [2] 71 5b }

  condition:
    any of them
}