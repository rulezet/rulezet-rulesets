rule TTP_XOR_WriteProcessMemory_ab30 {
  strings:
    $key_ab30 = { fc 42 [2] ce 60 [2] c8 55 [2] e6 55 [2] d9 49 }

  condition:
    any of them
}