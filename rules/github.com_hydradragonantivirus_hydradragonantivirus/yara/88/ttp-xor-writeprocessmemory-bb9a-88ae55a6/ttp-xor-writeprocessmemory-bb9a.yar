rule TTP_XOR_WriteProcessMemory_bb9a {
  strings:
    $key_bb9a = { ec e8 [2] de ca [2] d8 ff [2] f6 ff [2] c9 e3 }

  condition:
    any of them
}