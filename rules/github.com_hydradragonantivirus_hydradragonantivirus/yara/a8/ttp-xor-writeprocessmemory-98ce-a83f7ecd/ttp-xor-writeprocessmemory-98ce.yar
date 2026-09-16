rule TTP_XOR_WriteProcessMemory_98ce {
  strings:
    $key_98ce = { cf bc [2] fd 9e [2] fb ab [2] d5 ab [2] ea b7 }

  condition:
    any of them
}