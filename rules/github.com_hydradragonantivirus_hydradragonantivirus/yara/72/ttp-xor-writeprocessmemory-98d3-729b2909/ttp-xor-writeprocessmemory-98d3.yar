rule TTP_XOR_WriteProcessMemory_98d3 {
  strings:
    $key_98d3 = { cf a1 [2] fd 83 [2] fb b6 [2] d5 b6 [2] ea aa }

  condition:
    any of them
}