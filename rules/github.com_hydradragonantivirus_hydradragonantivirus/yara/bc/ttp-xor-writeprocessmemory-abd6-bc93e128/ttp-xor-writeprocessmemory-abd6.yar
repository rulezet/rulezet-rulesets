rule TTP_XOR_WriteProcessMemory_abd6 {
  strings:
    $key_abd6 = { fc a4 [2] ce 86 [2] c8 b3 [2] e6 b3 [2] d9 af }

  condition:
    any of them
}