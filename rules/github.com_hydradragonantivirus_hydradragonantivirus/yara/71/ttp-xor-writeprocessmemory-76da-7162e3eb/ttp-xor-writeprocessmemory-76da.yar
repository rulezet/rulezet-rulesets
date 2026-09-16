rule TTP_XOR_WriteProcessMemory_76da {
  strings:
    $key_76da = { 21 a8 [2] 13 8a [2] 15 bf [2] 3b bf [2] 04 a3 }

  condition:
    any of them
}