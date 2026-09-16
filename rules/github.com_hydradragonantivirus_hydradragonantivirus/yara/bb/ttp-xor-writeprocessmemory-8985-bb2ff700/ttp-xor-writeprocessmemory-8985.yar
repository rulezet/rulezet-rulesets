rule TTP_XOR_WriteProcessMemory_8985 {
  strings:
    $key_8985 = { de f7 [2] ec d5 [2] ea e0 [2] c4 e0 [2] fb fc }

  condition:
    any of them
}