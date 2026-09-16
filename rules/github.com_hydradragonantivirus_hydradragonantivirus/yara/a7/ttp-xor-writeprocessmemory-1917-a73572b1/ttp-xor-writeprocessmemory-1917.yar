rule TTP_XOR_WriteProcessMemory_1917 {
  strings:
    $key_1917 = { 4e 65 [2] 7c 47 [2] 7a 72 [2] 54 72 [2] 6b 6e }

  condition:
    any of them
}