rule TTP_XOR_WriteProcessMemory_98d9 {
  strings:
    $key_98d9 = { cf ab [2] fd 89 [2] fb bc [2] d5 bc [2] ea a0 }

  condition:
    any of them
}