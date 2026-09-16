rule TTP_XOR_WriteProcessMemory_e6da {
  strings:
    $key_e6da = { b1 a8 [2] 83 8a [2] 85 bf [2] ab bf [2] 94 a3 }

  condition:
    any of them
}