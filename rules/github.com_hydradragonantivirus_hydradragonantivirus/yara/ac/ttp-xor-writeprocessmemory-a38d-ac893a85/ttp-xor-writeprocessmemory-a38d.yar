rule TTP_XOR_WriteProcessMemory_a38d {
  strings:
    $key_a38d = { f4 ff [2] c6 dd [2] c0 e8 [2] ee e8 [2] d1 f4 }

  condition:
    any of them
}