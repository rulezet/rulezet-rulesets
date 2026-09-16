rule TTP_XOR_WriteProcessMemory_87da {
  strings:
    $key_87da = { d0 a8 [2] e2 8a [2] e4 bf [2] ca bf [2] f5 a3 }

  condition:
    any of them
}