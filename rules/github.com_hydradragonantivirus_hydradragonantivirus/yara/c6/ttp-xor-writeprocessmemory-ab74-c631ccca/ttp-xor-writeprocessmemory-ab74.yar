rule TTP_XOR_WriteProcessMemory_ab74 {
  strings:
    $key_ab74 = { fc 06 [2] ce 24 [2] c8 11 [2] e6 11 [2] d9 0d }

  condition:
    any of them
}