rule TTP_XOR_WriteProcessMemory_abef {
  strings:
    $key_abef = { fc 9d [2] ce bf [2] c8 8a [2] e6 8a [2] d9 96 }

  condition:
    any of them
}