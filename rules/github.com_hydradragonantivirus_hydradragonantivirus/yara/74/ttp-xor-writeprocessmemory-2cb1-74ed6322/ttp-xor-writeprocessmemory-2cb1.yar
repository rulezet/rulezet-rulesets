rule TTP_XOR_WriteProcessMemory_2cb1 {
  strings:
    $key_2cb1 = { 7b c3 [2] 49 e1 [2] 4f d4 [2] 61 d4 [2] 5e c8 }

  condition:
    any of them
}