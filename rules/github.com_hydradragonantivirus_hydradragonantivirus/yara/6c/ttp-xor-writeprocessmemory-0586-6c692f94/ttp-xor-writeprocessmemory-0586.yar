rule TTP_XOR_WriteProcessMemory_0586 {
  strings:
    $key_0586 = { 52 f4 [2] 60 d6 [2] 66 e3 [2] 48 e3 [2] 77 ff }

  condition:
    any of them
}