rule TTP_XOR_WriteProcessMemory_3be7 {
  strings:
    $key_3be7 = { 6c 95 [2] 5e b7 [2] 58 82 [2] 76 82 [2] 49 9e }

  condition:
    any of them
}