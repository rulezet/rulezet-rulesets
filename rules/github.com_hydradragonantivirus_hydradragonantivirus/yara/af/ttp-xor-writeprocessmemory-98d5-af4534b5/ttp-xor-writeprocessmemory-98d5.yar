rule TTP_XOR_WriteProcessMemory_98d5 {
  strings:
    $key_98d5 = { cf a7 [2] fd 85 [2] fb b0 [2] d5 b0 [2] ea ac }

  condition:
    any of them
}