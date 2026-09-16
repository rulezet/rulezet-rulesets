rule TTP_XOR_WriteProcessMemory_ab16 {
  strings:
    $key_ab16 = { fc 64 [2] ce 46 [2] c8 73 [2] e6 73 [2] d9 6f }

  condition:
    any of them
}