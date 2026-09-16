rule TTP_XOR_WriteProcessMemory_dfbe {
  strings:
    $key_dfbe = { 88 cc [2] ba ee [2] bc db [2] 92 db [2] ad c7 }

  condition:
    any of them
}