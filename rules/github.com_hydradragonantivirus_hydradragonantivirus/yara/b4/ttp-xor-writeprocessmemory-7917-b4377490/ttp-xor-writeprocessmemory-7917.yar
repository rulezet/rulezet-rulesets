rule TTP_XOR_WriteProcessMemory_7917 {
  strings:
    $key_7917 = { 2e 65 [2] 1c 47 [2] 1a 72 [2] 34 72 [2] 0b 6e }

  condition:
    any of them
}