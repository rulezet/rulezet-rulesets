rule TTP_XOR_WriteProcessMemory_d4da {
  strings:
    $key_d4da = { 83 a8 [2] b1 8a [2] b7 bf [2] 99 bf [2] a6 a3 }

  condition:
    any of them
}