rule TTP_XOR_WriteProcessMemory_7785 {
  strings:
    $key_7785 = { 20 f7 [2] 12 d5 [2] 14 e0 [2] 3a e0 [2] 05 fc }

  condition:
    any of them
}