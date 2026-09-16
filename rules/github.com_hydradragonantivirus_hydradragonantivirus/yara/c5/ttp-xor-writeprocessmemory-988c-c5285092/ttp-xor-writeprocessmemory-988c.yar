rule TTP_XOR_WriteProcessMemory_988c {
  strings:
    $key_988c = { cf fe [2] fd dc [2] fb e9 [2] d5 e9 [2] ea f5 }

  condition:
    any of them
}