rule TTP_XOR_WriteProcessMemory_a28d {
  strings:
    $key_a28d = { f5 ff [2] c7 dd [2] c1 e8 [2] ef e8 [2] d0 f4 }

  condition:
    any of them
}