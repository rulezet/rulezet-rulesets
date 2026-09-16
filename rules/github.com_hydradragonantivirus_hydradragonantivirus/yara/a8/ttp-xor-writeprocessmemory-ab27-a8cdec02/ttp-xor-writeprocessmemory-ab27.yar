rule TTP_XOR_WriteProcessMemory_ab27 {
  strings:
    $key_ab27 = { fc 55 [2] ce 77 [2] c8 42 [2] e6 42 [2] d9 5e }

  condition:
    any of them
}