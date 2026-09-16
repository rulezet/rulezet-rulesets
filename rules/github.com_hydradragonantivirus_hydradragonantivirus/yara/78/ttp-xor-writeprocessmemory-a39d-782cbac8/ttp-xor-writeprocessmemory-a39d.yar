rule TTP_XOR_WriteProcessMemory_a39d {
  strings:
    $key_a39d = { f4 ef [2] c6 cd [2] c0 f8 [2] ee f8 [2] d1 e4 }

  condition:
    any of them
}