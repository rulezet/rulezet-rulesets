rule TTP_XOR_WriteProcessMemory_abfa {
  strings:
    $key_abfa = { fc 88 [2] ce aa [2] c8 9f [2] e6 9f [2] d9 83 }

  condition:
    any of them
}