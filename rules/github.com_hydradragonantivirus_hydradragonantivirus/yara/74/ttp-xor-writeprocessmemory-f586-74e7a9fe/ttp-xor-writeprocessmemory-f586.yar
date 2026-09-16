rule TTP_XOR_WriteProcessMemory_f586 {
  strings:
    $key_f586 = { a2 f4 [2] 90 d6 [2] 96 e3 [2] b8 e3 [2] 87 ff }

  condition:
    any of them
}