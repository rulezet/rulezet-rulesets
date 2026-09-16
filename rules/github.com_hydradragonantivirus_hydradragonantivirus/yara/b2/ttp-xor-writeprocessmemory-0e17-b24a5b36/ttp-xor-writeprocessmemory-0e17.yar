rule TTP_XOR_WriteProcessMemory_0e17 {
  strings:
    $key_0e17 = { 59 65 [2] 6b 47 [2] 6d 72 [2] 43 72 [2] 7c 6e }

  condition:
    any of them
}