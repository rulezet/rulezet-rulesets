rule TTP_XOR_WriteProcessMemory_48da {
  strings:
    $key_48da = { 1f a8 [2] 2d 8a [2] 2b bf [2] 05 bf [2] 3a a3 }

  condition:
    any of them
}