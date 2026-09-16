rule TTP_XOR_WriteProcessMemory_cc8c {
  strings:
    $key_cc8c = { 9b fe [2] a9 dc [2] af e9 [2] 81 e9 [2] be f5 }

  condition:
    any of them
}