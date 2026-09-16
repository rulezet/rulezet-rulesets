rule TTP_XOR_WriteProcessMemory_988e {
  strings:
    $key_988e = { cf fc [2] fd de [2] fb eb [2] d5 eb [2] ea f7 }

  condition:
    any of them
}