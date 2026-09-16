rule TTP_XOR_WriteProcessMemory_8984 {
  strings:
    $key_8984 = { de f6 [2] ec d4 [2] ea e1 [2] c4 e1 [2] fb fd }

  condition:
    any of them
}