rule TTP_XOR_WriteProcessMemory_996a {
  strings:
    $key_996a = { ce 18 [2] fc 3a [2] fa 0f [2] d4 0f [2] eb 13 }

  condition:
    any of them
}