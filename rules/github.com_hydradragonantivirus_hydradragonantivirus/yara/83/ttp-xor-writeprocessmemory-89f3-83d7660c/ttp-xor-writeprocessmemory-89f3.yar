rule TTP_XOR_WriteProcessMemory_89f3 {
  strings:
    $key_89f3 = { de 81 [2] ec a3 [2] ea 96 [2] c4 96 [2] fb 8a }

  condition:
    any of them
}