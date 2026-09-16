rule TTP_XOR_WriteProcessMemory_3122 {
  strings:
    $key_3122 = { 66 50 [2] 54 72 [2] 52 47 [2] 7c 47 [2] 43 5b }

  condition:
    any of them
}