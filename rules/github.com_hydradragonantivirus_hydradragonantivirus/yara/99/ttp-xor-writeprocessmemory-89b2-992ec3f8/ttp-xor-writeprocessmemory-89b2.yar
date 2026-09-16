rule TTP_XOR_WriteProcessMemory_89b2 {
  strings:
    $key_89b2 = { de c0 [2] ec e2 [2] ea d7 [2] c4 d7 [2] fb cb }

  condition:
    any of them
}