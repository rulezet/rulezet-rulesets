rule TTP_XOR_WriteProcessMemory_995b {
  strings:
    $key_995b = { ce 29 [2] fc 0b [2] fa 3e [2] d4 3e [2] eb 22 }

  condition:
    any of them
}