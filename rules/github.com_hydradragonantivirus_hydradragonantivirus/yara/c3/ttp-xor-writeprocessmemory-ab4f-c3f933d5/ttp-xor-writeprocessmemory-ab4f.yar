rule TTP_XOR_WriteProcessMemory_ab4f {
  strings:
    $key_ab4f = { fc 3d [2] ce 1f [2] c8 2a [2] e6 2a [2] d9 36 }

  condition:
    any of them
}