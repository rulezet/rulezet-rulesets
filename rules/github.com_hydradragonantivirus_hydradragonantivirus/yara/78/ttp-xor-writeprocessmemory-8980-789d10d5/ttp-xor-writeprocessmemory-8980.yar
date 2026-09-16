rule TTP_XOR_WriteProcessMemory_8980 {
  strings:
    $key_8980 = { de f2 [2] ec d0 [2] ea e5 [2] c4 e5 [2] fb f9 }

  condition:
    any of them
}