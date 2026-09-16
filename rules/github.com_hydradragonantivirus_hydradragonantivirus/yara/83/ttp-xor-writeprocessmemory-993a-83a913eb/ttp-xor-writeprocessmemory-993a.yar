rule TTP_XOR_WriteProcessMemory_993a {
  strings:
    $key_993a = { ce 48 [2] fc 6a [2] fa 5f [2] d4 5f [2] eb 43 }

  condition:
    any of them
}