rule TTP_XOR_WriteProcessMemory_abf5 {
  strings:
    $key_abf5 = { fc 87 [2] ce a5 [2] c8 90 [2] e6 90 [2] d9 8c }

  condition:
    any of them
}