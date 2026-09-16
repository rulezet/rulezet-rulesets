rule TTP_XOR_WriteProcessMemory_6586 {
  strings:
    $key_6586 = { 32 f4 [2] 00 d6 [2] 06 e3 [2] 28 e3 [2] 17 ff }

  condition:
    any of them
}