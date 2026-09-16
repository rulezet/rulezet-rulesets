rule TTP_XOR_WriteProcessMemory_994d {
  strings:
    $key_994d = { ce 3f [2] fc 1d [2] fa 28 [2] d4 28 [2] eb 34 }

  condition:
    any of them
}