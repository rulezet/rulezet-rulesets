rule TTP_XOR_WriteProcessMemory_8956 {
  strings:
    $key_8956 = { de 24 [2] ec 06 [2] ea 33 [2] c4 33 [2] fb 2f }

  condition:
    any of them
}