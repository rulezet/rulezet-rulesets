rule TTP_XOR_WriteProcessMemory_1386 {
  strings:
    $key_1386 = { 44 f4 [2] 76 d6 [2] 70 e3 [2] 5e e3 [2] 61 ff }

  condition:
    any of them
}