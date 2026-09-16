rule TTP_XOR_WriteProcessMemory_abf0 {
  strings:
    $key_abf0 = { fc 82 [2] ce a0 [2] c8 95 [2] e6 95 [2] d9 89 }

  condition:
    any of them
}