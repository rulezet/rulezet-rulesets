rule TTP_XOR_WriteProcessMemory_4586 {
  strings:
    $key_4586 = { 12 f4 [2] 20 d6 [2] 26 e3 [2] 08 e3 [2] 37 ff }

  condition:
    any of them
}