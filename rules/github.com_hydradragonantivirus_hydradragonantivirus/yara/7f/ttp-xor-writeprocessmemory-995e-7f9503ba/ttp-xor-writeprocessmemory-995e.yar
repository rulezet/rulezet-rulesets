rule TTP_XOR_WriteProcessMemory_995e {
  strings:
    $key_995e = { ce 2c [2] fc 0e [2] fa 3b [2] d4 3b [2] eb 27 }

  condition:
    any of them
}