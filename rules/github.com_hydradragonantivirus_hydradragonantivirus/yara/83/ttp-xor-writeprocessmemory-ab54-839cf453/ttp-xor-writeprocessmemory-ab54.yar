rule TTP_XOR_WriteProcessMemory_ab54 {
  strings:
    $key_ab54 = { fc 26 [2] ce 04 [2] c8 31 [2] e6 31 [2] d9 2d }

  condition:
    any of them
}