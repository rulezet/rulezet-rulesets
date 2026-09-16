rule TTP_XOR_WriteProcessMemory_99ce {
  strings:
    $key_99ce = { ce bc [2] fc 9e [2] fa ab [2] d4 ab [2] eb b7 }

  condition:
    any of them
}