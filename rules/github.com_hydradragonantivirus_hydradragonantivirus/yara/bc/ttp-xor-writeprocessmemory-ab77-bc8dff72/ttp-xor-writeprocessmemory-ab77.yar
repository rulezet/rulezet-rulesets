rule TTP_XOR_WriteProcessMemory_ab77 {
  strings:
    $key_ab77 = { fc 05 [2] ce 27 [2] c8 12 [2] e6 12 [2] d9 0e }

  condition:
    any of them
}