rule TTP_XOR_WriteProcessMemory_8900 {
  strings:
    $key_8900 = { de 72 [2] ec 50 [2] ea 65 [2] c4 65 [2] fb 79 }

  condition:
    any of them
}