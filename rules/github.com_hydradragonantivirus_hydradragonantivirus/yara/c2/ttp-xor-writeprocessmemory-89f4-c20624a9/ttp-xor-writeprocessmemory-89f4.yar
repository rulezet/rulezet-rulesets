rule TTP_XOR_WriteProcessMemory_89f4 {
  strings:
    $key_89f4 = { de 86 [2] ec a4 [2] ea 91 [2] c4 91 [2] fb 8d }

  condition:
    any of them
}