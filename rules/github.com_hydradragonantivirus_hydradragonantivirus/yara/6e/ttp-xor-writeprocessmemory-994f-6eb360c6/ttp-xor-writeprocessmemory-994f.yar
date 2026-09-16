rule TTP_XOR_WriteProcessMemory_994f {
  strings:
    $key_994f = { ce 3d [2] fc 1f [2] fa 2a [2] d4 2a [2] eb 36 }

  condition:
    any of them
}