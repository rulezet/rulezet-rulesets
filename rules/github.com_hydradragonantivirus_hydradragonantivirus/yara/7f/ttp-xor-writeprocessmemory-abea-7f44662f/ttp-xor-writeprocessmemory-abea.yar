rule TTP_XOR_WriteProcessMemory_abea {
  strings:
    $key_abea = { fc 98 [2] ce ba [2] c8 8f [2] e6 8f [2] d9 93 }

  condition:
    any of them
}