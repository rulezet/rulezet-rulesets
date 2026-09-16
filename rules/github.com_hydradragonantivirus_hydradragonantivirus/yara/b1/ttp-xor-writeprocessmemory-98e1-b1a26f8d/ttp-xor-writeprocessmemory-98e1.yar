rule TTP_XOR_WriteProcessMemory_98e1 {
  strings:
    $key_98e1 = { cf 93 [2] fd b1 [2] fb 84 [2] d5 84 [2] ea 98 }

  condition:
    any of them
}