rule TTP_XOR_WriteProcessMemory_89f9 {
  strings:
    $key_89f9 = { de 8b [2] ec a9 [2] ea 9c [2] c4 9c [2] fb 80 }

  condition:
    any of them
}