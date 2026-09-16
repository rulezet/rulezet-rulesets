rule TTP_XOR_WriteProcessMemory_959a {
  strings:
    $key_959a = { c2 e8 [2] f0 ca [2] f6 ff [2] d8 ff [2] e7 e3 }

  condition:
    any of them
}