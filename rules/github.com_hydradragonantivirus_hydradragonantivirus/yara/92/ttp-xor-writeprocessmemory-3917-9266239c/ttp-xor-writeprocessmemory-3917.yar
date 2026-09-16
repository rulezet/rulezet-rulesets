rule TTP_XOR_WriteProcessMemory_3917 {
  strings:
    $key_3917 = { 6e 65 [2] 5c 47 [2] 5a 72 [2] 74 72 [2] 4b 6e }

  condition:
    any of them
}