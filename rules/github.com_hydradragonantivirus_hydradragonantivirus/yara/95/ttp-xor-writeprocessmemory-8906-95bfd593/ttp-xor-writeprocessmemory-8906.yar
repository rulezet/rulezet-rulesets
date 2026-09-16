rule TTP_XOR_WriteProcessMemory_8906 {
  strings:
    $key_8906 = { de 74 [2] ec 56 [2] ea 63 [2] c4 63 [2] fb 7f }

  condition:
    any of them
}