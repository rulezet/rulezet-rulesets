rule TTP_XOR_WriteProcessMemory_ab4a {
  strings:
    $key_ab4a = { fc 38 [2] ce 1a [2] c8 2f [2] e6 2f [2] d9 33 }

  condition:
    any of them
}