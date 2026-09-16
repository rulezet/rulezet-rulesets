rule TTP_XOR_WriteProcessMemory_ab5d {
  strings:
    $key_ab5d = { fc 2f [2] ce 0d [2] c8 38 [2] e6 38 [2] d9 24 }

  condition:
    any of them
}