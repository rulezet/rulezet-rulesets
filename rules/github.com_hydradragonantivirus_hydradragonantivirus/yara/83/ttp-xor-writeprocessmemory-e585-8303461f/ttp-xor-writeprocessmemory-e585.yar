rule TTP_XOR_WriteProcessMemory_e585 {
  strings:
    $key_e585 = { b2 f7 [2] 80 d5 [2] 86 e0 [2] a8 e0 [2] 97 fc }

  condition:
    any of them
}