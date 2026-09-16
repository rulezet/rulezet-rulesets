rule TTP_XOR_WriteProcessMemory_e591 {
  strings:
    $key_e591 = { b2 e3 [2] 80 c1 [2] 86 f4 [2] a8 f4 [2] 97 e8 }

  condition:
    any of them
}