rule TTP_XOR_WriteProcessMemory_abbb {
  strings:
    $key_abbb = { fc c9 [2] ce eb [2] c8 de [2] e6 de [2] d9 c2 }

  condition:
    any of them
}