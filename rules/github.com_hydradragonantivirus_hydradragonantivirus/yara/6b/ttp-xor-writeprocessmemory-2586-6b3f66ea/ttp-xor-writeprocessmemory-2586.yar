rule TTP_XOR_WriteProcessMemory_2586 {
  strings:
    $key_2586 = { 72 f4 [2] 40 d6 [2] 46 e3 [2] 68 e3 [2] 57 ff }

  condition:
    any of them
}