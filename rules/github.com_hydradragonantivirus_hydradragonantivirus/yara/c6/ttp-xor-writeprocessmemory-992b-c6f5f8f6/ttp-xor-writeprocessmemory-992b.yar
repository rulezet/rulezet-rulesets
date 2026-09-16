rule TTP_XOR_WriteProcessMemory_992b {
  strings:
    $key_992b = { ce 59 [2] fc 7b [2] fa 4e [2] d4 4e [2] eb 52 }

  condition:
    any of them
}