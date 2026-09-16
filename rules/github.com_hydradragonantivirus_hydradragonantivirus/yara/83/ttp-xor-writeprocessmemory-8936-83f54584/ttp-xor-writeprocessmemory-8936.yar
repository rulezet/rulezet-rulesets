rule TTP_XOR_WriteProcessMemory_8936 {
  strings:
    $key_8936 = { de 44 [2] ec 66 [2] ea 53 [2] c4 53 [2] fb 4f }

  condition:
    any of them
}