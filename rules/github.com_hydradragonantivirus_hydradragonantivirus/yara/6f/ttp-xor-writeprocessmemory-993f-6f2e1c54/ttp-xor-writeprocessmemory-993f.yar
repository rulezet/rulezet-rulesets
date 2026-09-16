rule TTP_XOR_WriteProcessMemory_993f {
  strings:
    $key_993f = { ce 4d [2] fc 6f [2] fa 5a [2] d4 5a [2] eb 46 }

  condition:
    any of them
}