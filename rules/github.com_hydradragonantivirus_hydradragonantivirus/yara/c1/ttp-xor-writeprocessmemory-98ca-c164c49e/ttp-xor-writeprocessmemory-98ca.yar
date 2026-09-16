rule TTP_XOR_WriteProcessMemory_98ca {
  strings:
    $key_98ca = { cf b8 [2] fd 9a [2] fb af [2] d5 af [2] ea b3 }

  condition:
    any of them
}