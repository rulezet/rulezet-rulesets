rule TTP_XOR_WriteProcessMemory_98c3 {
  strings:
    $key_98c3 = { cf b1 [2] fd 93 [2] fb a6 [2] d5 a6 [2] ea ba }

  condition:
    any of them
}