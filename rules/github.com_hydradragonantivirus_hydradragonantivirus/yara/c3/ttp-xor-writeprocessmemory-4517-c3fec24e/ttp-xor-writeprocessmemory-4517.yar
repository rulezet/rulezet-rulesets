rule TTP_XOR_WriteProcessMemory_4517 {
  strings:
    $key_4517 = { 12 65 [2] 20 47 [2] 26 72 [2] 08 72 [2] 37 6e }

  condition:
    any of them
}