rule TTP_XOR_WriteProcessMemory_8943 {
  strings:
    $key_8943 = { de 31 [2] ec 13 [2] ea 26 [2] c4 26 [2] fb 3a }

  condition:
    any of them
}