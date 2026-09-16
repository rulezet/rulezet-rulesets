rule TTP_XOR_WriteProcessMemory_8932 {
  strings:
    $key_8932 = { de 40 [2] ec 62 [2] ea 57 [2] c4 57 [2] fb 4b }

  condition:
    any of them
}