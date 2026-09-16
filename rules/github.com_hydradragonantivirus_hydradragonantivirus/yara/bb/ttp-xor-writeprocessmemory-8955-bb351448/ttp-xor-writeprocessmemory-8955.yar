rule TTP_XOR_WriteProcessMemory_8955 {
  strings:
    $key_8955 = { de 27 [2] ec 05 [2] ea 30 [2] c4 30 [2] fb 2c }

  condition:
    any of them
}