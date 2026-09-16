rule TTP_XOR_WriteProcessMemory_3921 {
  strings:
    $key_3921 = { 6e 53 [2] 5c 71 [2] 5a 44 [2] 74 44 [2] 4b 58 }

  condition:
    any of them
}