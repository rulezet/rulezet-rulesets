rule TTP_XOR_WriteProcessMemory_8d8e {
  strings:
    $key_8d8e = { da fc [2] e8 de [2] ee eb [2] c0 eb [2] ff f7 }

  condition:
    any of them
}