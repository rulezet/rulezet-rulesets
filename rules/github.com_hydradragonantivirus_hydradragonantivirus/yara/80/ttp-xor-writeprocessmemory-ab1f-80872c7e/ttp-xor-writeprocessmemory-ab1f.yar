rule TTP_XOR_WriteProcessMemory_ab1f {
  strings:
    $key_ab1f = { fc 6d [2] ce 4f [2] c8 7a [2] e6 7a [2] d9 66 }

  condition:
    any of them
}