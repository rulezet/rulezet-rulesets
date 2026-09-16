rule TTP_XOR_WriteProcessMemory_98c1 {
  strings:
    $key_98c1 = { cf b3 [2] fd 91 [2] fb a4 [2] d5 a4 [2] ea b8 }

  condition:
    any of them
}