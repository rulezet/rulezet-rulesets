rule TTP_XOR_WriteProcessMemory_98c2 {
  strings:
    $key_98c2 = { cf b0 [2] fd 92 [2] fb a7 [2] d5 a7 [2] ea bb }

  condition:
    any of them
}