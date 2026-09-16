rule TTP_XOR_WriteProcessMemory_98dd {
  strings:
    $key_98dd = { cf af [2] fd 8d [2] fb b8 [2] d5 b8 [2] ea a4 }

  condition:
    any of them
}