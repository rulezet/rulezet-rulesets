rule TTP_XOR_WriteProcessMemory_abe0 {
  strings:
    $key_abe0 = { fc 92 [2] ce b0 [2] c8 85 [2] e6 85 [2] d9 99 }

  condition:
    any of them
}