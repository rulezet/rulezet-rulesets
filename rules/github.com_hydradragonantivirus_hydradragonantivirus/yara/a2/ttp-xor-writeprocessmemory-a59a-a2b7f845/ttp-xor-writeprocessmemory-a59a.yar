rule TTP_XOR_WriteProcessMemory_a59a {
  strings:
    $key_a59a = { f2 e8 [2] c0 ca [2] c6 ff [2] e8 ff [2] d7 e3 }

  condition:
    any of them
}