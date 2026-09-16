rule TTP_XOR_WriteProcessMemory_957a {
  strings:
    $key_957a = { c2 08 [2] f0 2a [2] f6 1f [2] d8 1f [2] e7 03 }

  condition:
    any of them
}