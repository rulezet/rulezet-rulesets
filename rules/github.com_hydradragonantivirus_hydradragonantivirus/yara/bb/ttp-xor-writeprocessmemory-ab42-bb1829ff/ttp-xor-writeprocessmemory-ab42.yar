rule TTP_XOR_WriteProcessMemory_ab42 {
  strings:
    $key_ab42 = { fc 30 [2] ce 12 [2] c8 27 [2] e6 27 [2] d9 3b }

  condition:
    any of them
}