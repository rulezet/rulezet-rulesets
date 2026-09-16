rule TTP_XOR_WriteProcessMemory_8942 {
  strings:
    $key_8942 = { de 30 [2] ec 12 [2] ea 27 [2] c4 27 [2] fb 3b }

  condition:
    any of them
}