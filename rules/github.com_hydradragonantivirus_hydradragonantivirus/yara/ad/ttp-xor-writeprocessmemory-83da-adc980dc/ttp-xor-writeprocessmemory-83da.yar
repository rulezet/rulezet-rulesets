rule TTP_XOR_WriteProcessMemory_83da {
  strings:
    $key_83da = { d4 a8 [2] e6 8a [2] e0 bf [2] ce bf [2] f1 a3 }

  condition:
    any of them
}