rule TTP_XOR_WriteProcessMemory_b899 {
  strings:
    $key_b899 = { ef eb [2] dd c9 [2] db fc [2] f5 fc [2] ca e0 }

  condition:
    any of them
}