rule TTP_XOR_WriteProcessMemory_98dc {
  strings:
    $key_98dc = { cf ae [2] fd 8c [2] fb b9 [2] d5 b9 [2] ea a5 }

  condition:
    any of them
}