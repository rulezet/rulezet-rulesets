rule TTP_XOR_WriteProcessMemory_abeb {
  strings:
    $key_abeb = { fc 99 [2] ce bb [2] c8 8e [2] e6 8e [2] d9 92 }

  condition:
    any of them
}