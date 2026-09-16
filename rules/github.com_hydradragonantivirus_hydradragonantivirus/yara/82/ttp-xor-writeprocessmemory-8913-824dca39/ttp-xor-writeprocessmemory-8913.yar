rule TTP_XOR_WriteProcessMemory_8913 {
  strings:
    $key_8913 = { de 61 [2] ec 43 [2] ea 76 [2] c4 76 [2] fb 6a }

  condition:
    any of them
}