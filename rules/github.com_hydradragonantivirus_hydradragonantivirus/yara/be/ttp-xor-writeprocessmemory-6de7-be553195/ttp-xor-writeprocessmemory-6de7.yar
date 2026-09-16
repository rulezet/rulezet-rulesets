rule TTP_XOR_WriteProcessMemory_6de7 {
  strings:
    $key_6de7 = { 3a 95 [2] 08 b7 [2] 0e 82 [2] 20 82 [2] 1f 9e }

  condition:
    any of them
}