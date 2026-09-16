rule TTP_XOR_WriteProcessMemory_ab2d {
  strings:
    $key_ab2d = { fc 5f [2] ce 7d [2] c8 48 [2] e6 48 [2] d9 54 }

  condition:
    any of them
}