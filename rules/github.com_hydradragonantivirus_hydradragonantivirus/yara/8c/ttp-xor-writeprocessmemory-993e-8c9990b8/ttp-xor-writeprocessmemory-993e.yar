rule TTP_XOR_WriteProcessMemory_993e {
  strings:
    $key_993e = { ce 4c [2] fc 6e [2] fa 5b [2] d4 5b [2] eb 47 }

  condition:
    any of them
}