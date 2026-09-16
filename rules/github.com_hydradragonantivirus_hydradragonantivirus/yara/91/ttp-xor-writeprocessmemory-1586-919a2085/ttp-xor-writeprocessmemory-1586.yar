rule TTP_XOR_WriteProcessMemory_1586 {
  strings:
    $key_1586 = { 42 f4 [2] 70 d6 [2] 76 e3 [2] 58 e3 [2] 67 ff }

  condition:
    any of them
}