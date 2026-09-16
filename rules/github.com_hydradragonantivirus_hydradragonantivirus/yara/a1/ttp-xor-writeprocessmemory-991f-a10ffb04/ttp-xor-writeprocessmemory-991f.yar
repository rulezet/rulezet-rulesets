rule TTP_XOR_WriteProcessMemory_991f {
  strings:
    $key_991f = { ce 6d [2] fc 4f [2] fa 7a [2] d4 7a [2] eb 66 }

  condition:
    any of them
}