rule TTP_XOR_WriteProcessMemory_dfbb {
  strings:
    $key_dfbb = { 88 c9 [2] ba eb [2] bc de [2] 92 de [2] ad c2 }

  condition:
    any of them
}