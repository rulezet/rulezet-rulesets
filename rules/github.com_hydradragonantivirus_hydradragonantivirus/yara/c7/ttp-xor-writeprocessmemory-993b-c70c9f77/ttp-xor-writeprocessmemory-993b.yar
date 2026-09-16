rule TTP_XOR_WriteProcessMemory_993b {
  strings:
    $key_993b = { ce 49 [2] fc 6b [2] fa 5e [2] d4 5e [2] eb 42 }

  condition:
    any of them
}