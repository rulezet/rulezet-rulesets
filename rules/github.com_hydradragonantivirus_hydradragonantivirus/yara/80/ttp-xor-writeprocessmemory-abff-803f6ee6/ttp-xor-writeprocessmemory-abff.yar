rule TTP_XOR_WriteProcessMemory_abff {
  strings:
    $key_abff = { fc 8d [2] ce af [2] c8 9a [2] e6 9a [2] d9 86 }

  condition:
    any of them
}