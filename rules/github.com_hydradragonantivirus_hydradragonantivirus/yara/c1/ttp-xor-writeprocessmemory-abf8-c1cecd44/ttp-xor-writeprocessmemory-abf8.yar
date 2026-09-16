rule TTP_XOR_WriteProcessMemory_abf8 {
  strings:
    $key_abf8 = { fc 8a [2] ce a8 [2] c8 9d [2] e6 9d [2] d9 81 }

  condition:
    any of them
}