rule TTP_XOR_WriteProcessMemory_ab72 {
  strings:
    $key_ab72 = { fc 00 [2] ce 22 [2] c8 17 [2] e6 17 [2] d9 0b }

  condition:
    any of them
}