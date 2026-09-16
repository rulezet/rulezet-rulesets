rule TTP_XOR_WriteProcessMemory_ab41 {
  strings:
    $key_ab41 = { fc 33 [2] ce 11 [2] c8 24 [2] e6 24 [2] d9 38 }

  condition:
    any of them
}