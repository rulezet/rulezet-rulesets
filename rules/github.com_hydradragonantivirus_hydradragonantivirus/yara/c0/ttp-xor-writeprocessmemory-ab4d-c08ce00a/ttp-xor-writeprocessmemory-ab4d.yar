rule TTP_XOR_WriteProcessMemory_ab4d {
  strings:
    $key_ab4d = { fc 3f [2] ce 1d [2] c8 28 [2] e6 28 [2] d9 34 }

  condition:
    any of them
}