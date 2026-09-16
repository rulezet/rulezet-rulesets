rule TTP_XOR_WriteProcessMemory_a39a {
  strings:
    $key_a39a = { f4 e8 [2] c6 ca [2] c0 ff [2] ee ff [2] d1 e3 }

  condition:
    any of them
}