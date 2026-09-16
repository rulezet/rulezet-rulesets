rule TTP_XOR_WriteProcessMemory_990f {
  strings:
    $key_990f = { ce 7d [2] fc 5f [2] fa 6a [2] d4 6a [2] eb 76 }

  condition:
    any of them
}