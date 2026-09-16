rule TTP_XOR_WriteProcessMemory_98ad {
  strings:
    $key_98ad = { cf df [2] fd fd [2] fb c8 [2] d5 c8 [2] ea d4 }

  condition:
    any of them
}