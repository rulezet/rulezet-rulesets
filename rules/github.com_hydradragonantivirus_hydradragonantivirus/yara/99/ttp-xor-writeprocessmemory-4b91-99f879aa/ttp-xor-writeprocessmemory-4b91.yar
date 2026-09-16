rule TTP_XOR_WriteProcessMemory_4b91 {
  strings:
    $key_4b91 = { 1c e3 [2] 2e c1 [2] 28 f4 [2] 06 f4 [2] 39 e8 }

  condition:
    any of them
}