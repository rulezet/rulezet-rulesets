rule TTP_XOR_WriteProcessMemory_89f8 {
  strings:
    $key_89f8 = { de 8a [2] ec a8 [2] ea 9d [2] c4 9d [2] fb 81 }

  condition:
    any of them
}