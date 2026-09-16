rule TTP_XOR_WriteProcessMemory_5262 {
  strings:
    $key_5262 = { 05 10 [2] 37 32 [2] 31 07 [2] 1f 07 [2] 20 1b }

  condition:
    any of them
}