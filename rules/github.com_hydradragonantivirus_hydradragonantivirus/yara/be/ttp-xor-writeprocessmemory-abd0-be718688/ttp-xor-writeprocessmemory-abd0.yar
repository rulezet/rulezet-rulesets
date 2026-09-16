rule TTP_XOR_WriteProcessMemory_abd0 {
  strings:
    $key_abd0 = { fc a2 [2] ce 80 [2] c8 b5 [2] e6 b5 [2] d9 a9 }

  condition:
    any of them
}