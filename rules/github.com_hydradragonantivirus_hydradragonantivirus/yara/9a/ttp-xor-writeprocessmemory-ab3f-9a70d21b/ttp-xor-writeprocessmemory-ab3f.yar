rule TTP_XOR_WriteProcessMemory_ab3f {
  strings:
    $key_ab3f = { fc 4d [2] ce 6f [2] c8 5a [2] e6 5a [2] d9 46 }

  condition:
    any of them
}