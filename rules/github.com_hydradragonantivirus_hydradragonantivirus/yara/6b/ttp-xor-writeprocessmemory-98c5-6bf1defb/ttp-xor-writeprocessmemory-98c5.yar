rule TTP_XOR_WriteProcessMemory_98c5 {
  strings:
    $key_98c5 = { cf b7 [2] fd 95 [2] fb a0 [2] d5 a0 [2] ea bc }

  condition:
    any of them
}