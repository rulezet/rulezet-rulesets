rule TTP_XOR_WriteProcessMemory_e586 {
  strings:
    $key_e586 = { b2 f4 [2] 80 d6 [2] 86 e3 [2] a8 e3 [2] 97 ff }

  condition:
    any of them
}