rule TTP_XOR_WriteProcessMemory_ab12 {
  strings:
    $key_ab12 = { fc 60 [2] ce 42 [2] c8 77 [2] e6 77 [2] d9 6b }

  condition:
    any of them
}