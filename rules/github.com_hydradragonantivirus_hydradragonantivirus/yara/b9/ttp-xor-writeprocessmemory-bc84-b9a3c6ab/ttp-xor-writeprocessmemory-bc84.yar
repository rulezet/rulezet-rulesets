rule TTP_XOR_WriteProcessMemory_bc84 {
  strings:
    $key_bc84 = { eb f6 [2] d9 d4 [2] df e1 [2] f1 e1 [2] ce fd }

  condition:
    any of them
}