rule TTP_XOR_WriteProcessMemory_98e2 {
  strings:
    $key_98e2 = { cf 90 [2] fd b2 [2] fb 87 [2] d5 87 [2] ea 9b }

  condition:
    any of them
}