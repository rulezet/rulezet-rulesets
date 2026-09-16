rule TTP_XOR_WriteProcessMemory_0086 {
  strings:
    $key_0086 = { 57 f4 [2] 65 d6 [2] 63 e3 [2] 4d e3 [2] 72 ff }

  condition:
    any of them
}