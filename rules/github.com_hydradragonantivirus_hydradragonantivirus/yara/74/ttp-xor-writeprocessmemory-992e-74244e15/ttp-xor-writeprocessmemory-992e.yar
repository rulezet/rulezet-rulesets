rule TTP_XOR_WriteProcessMemory_992e {
  strings:
    $key_992e = { ce 5c [2] fc 7e [2] fa 4b [2] d4 4b [2] eb 57 }

  condition:
    any of them
}