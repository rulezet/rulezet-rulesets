rule TTP_XOR_WriteProcessMemory_5d17 {
  strings:
    $key_5d17 = { 0a 65 [2] 38 47 [2] 3e 72 [2] 10 72 [2] 2f 6e }

  condition:
    any of them
}