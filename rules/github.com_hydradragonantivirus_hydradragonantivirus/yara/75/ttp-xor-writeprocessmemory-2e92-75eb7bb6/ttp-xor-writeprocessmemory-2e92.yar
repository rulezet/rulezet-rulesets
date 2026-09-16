rule TTP_XOR_WriteProcessMemory_2e92 {
  strings:
    $key_2e92 = { 79 e0 [2] 4b c2 [2] 4d f7 [2] 63 f7 [2] 5c eb }

  condition:
    any of them
}