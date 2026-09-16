rule TTP_XOR_WriteProcessMemory_ed85 {
  strings:
    $key_ed85 = { ba f7 [2] 88 d5 [2] 8e e0 [2] a0 e0 [2] 9f fc }

  condition:
    any of them
}