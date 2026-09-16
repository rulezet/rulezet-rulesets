rule TTP_XOR_WriteProcessMemory_992f {
  strings:
    $key_992f = { ce 5d [2] fc 7f [2] fa 4a [2] d4 4a [2] eb 56 }

  condition:
    any of them
}