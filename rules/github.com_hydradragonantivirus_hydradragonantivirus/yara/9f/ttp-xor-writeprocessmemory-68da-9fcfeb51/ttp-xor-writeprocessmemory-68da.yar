rule TTP_XOR_WriteProcessMemory_68da {
  strings:
    $key_68da = { 3f a8 [2] 0d 8a [2] 0b bf [2] 25 bf [2] 1a a3 }

  condition:
    any of them
}