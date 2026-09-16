rule TTP_XOR_WriteProcessMemory_89f7 {
  strings:
    $key_89f7 = { de 85 [2] ec a7 [2] ea 92 [2] c4 92 [2] fb 8e }

  condition:
    any of them
}