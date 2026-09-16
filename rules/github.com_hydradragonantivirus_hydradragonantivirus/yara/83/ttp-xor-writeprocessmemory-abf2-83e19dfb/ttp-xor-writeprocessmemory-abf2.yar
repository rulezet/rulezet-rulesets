rule TTP_XOR_WriteProcessMemory_abf2 {
  strings:
    $key_abf2 = { fc 80 [2] ce a2 [2] c8 97 [2] e6 97 [2] d9 8b }

  condition:
    any of them
}