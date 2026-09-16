rule TTP_XOR_WriteProcessMemory_abd1 {
  strings:
    $key_abd1 = { fc a3 [2] ce 81 [2] c8 b4 [2] e6 b4 [2] d9 a8 }

  condition:
    any of them
}