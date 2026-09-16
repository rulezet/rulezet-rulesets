rule TTP_XOR_WriteProcessMemory_990b {
  strings:
    $key_990b = { ce 79 [2] fc 5b [2] fa 6e [2] d4 6e [2] eb 72 }

  condition:
    any of them
}