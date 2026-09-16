rule TTP_XOR_WriteProcessMemory_38da {
  strings:
    $key_38da = { 6f a8 [2] 5d 8a [2] 5b bf [2] 75 bf [2] 4a a3 }

  condition:
    any of them
}