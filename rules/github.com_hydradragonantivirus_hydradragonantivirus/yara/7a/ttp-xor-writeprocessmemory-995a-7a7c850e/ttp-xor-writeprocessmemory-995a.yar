rule TTP_XOR_WriteProcessMemory_995a {
  strings:
    $key_995a = { ce 28 [2] fc 0a [2] fa 3f [2] d4 3f [2] eb 23 }

  condition:
    any of them
}