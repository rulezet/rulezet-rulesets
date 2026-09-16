rule TTP_XOR_WriteProcessMemory_4017 {
  strings:
    $key_4017 = { 17 65 [2] 25 47 [2] 23 72 [2] 0d 72 [2] 32 6e }

  condition:
    any of them
}