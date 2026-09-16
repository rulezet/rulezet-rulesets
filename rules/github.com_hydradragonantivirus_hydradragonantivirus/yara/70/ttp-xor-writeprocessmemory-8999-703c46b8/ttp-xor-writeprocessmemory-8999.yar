rule TTP_XOR_WriteProcessMemory_8999 {
  strings:
    $key_8999 = { de eb [2] ec c9 [2] ea fc [2] c4 fc [2] fb e0 }

  condition:
    any of them
}