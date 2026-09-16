rule TTP_XOR_WriteProcessMemory_992d {
  strings:
    $key_992d = { ce 5f [2] fc 7d [2] fa 48 [2] d4 48 [2] eb 54 }

  condition:
    any of them
}