rule TTP_XOR_WriteProcessMemory_ab11 {
  strings:
    $key_ab11 = { fc 63 [2] ce 41 [2] c8 74 [2] e6 74 [2] d9 68 }

  condition:
    any of them
}