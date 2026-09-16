rule TTP_XOR_WriteProcessMemory_98d2 {
  strings:
    $key_98d2 = { cf a0 [2] fd 82 [2] fb b7 [2] d5 b7 [2] ea ab }

  condition:
    any of them
}