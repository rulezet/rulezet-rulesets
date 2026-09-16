rule TTP_XOR_WriteProcessMemory_78da {
  strings:
    $key_78da = { 2f a8 [2] 1d 8a [2] 1b bf [2] 35 bf [2] 0a a3 }

  condition:
    any of them
}