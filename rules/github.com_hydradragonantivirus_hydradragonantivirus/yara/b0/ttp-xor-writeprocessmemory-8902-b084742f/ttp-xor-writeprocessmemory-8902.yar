rule TTP_XOR_WriteProcessMemory_8902 {
  strings:
    $key_8902 = { de 70 [2] ec 52 [2] ea 67 [2] c4 67 [2] fb 7b }

  condition:
    any of them
}