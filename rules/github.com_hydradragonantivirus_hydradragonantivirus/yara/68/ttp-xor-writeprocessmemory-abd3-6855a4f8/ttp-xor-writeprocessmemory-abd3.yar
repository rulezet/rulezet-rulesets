rule TTP_XOR_WriteProcessMemory_abd3 {
  strings:
    $key_abd3 = { fc a1 [2] ce 83 [2] c8 b6 [2] e6 b6 [2] d9 aa }

  condition:
    any of them
}