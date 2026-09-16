rule TTP_XOR_WriteProcessMemory_8946 {
  strings:
    $key_8946 = { de 34 [2] ec 16 [2] ea 23 [2] c4 23 [2] fb 3f }

  condition:
    any of them
}