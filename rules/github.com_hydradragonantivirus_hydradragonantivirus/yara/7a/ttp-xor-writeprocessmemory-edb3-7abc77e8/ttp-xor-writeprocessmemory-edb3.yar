rule TTP_XOR_WriteProcessMemory_edb3 {
  strings:
    $key_edb3 = { ba c1 [2] 88 e3 [2] 8e d6 [2] a0 d6 [2] 9f ca }

  condition:
    any of them
}