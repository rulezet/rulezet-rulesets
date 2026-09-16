rule TTP_XOR_WriteProcessMemory_ab06 {
  strings:
    $key_ab06 = { fc 74 [2] ce 56 [2] c8 63 [2] e6 63 [2] d9 7f }

  condition:
    any of them
}