rule TTP_XOR_WriteProcessMemory_abd7 {
  strings:
    $key_abd7 = { fc a5 [2] ce 87 [2] c8 b2 [2] e6 b2 [2] d9 ae }

  condition:
    any of them
}