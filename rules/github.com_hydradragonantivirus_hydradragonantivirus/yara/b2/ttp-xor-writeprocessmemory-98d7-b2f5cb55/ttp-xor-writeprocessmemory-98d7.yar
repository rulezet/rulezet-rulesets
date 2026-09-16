rule TTP_XOR_WriteProcessMemory_98d7 {
  strings:
    $key_98d7 = { cf a5 [2] fd 87 [2] fb b2 [2] d5 b2 [2] ea ae }

  condition:
    any of them
}