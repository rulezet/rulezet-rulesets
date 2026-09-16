rule TTP_XOR_WriteProcessMemory_ab7f {
  strings:
    $key_ab7f = { fc 0d [2] ce 2f [2] c8 1a [2] e6 1a [2] d9 06 }

  condition:
    any of them
}