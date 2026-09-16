rule TTP_XOR_WriteProcessMemory_98d0 {
  strings:
    $key_98d0 = { cf a2 [2] fd 80 [2] fb b5 [2] d5 b5 [2] ea a9 }

  condition:
    any of them
}