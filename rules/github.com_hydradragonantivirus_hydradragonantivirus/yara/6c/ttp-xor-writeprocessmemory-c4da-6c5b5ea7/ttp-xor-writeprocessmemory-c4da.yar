rule TTP_XOR_WriteProcessMemory_c4da {
  strings:
    $key_c4da = { 93 a8 [2] a1 8a [2] a7 bf [2] 89 bf [2] b6 a3 }

  condition:
    any of them
}