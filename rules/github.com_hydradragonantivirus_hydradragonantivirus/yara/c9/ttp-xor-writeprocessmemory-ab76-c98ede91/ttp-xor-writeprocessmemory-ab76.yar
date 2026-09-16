rule TTP_XOR_WriteProcessMemory_ab76 {
  strings:
    $key_ab76 = { fc 04 [2] ce 26 [2] c8 13 [2] e6 13 [2] d9 0f }

  condition:
    any of them
}