rule TTP_XOR_WriteProcessMemory_abab {
  strings:
    $key_abab = { fc d9 [2] ce fb [2] c8 ce [2] e6 ce [2] d9 d2 }

  condition:
    any of them
}