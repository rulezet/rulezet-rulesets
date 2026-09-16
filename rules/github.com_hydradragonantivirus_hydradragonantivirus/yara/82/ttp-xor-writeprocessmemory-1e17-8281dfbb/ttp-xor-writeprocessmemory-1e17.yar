rule TTP_XOR_WriteProcessMemory_1e17 {
  strings:
    $key_1e17 = { 49 65 [2] 7b 47 [2] 7d 72 [2] 53 72 [2] 6c 6e }

  condition:
    any of them
}