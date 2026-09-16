rule TTP_XOR_WriteProcessMemory_1921 {
  strings:
    $key_1921 = { 4e 53 [2] 7c 71 [2] 7a 44 [2] 54 44 [2] 6b 58 }

  condition:
    any of them
}