rule TTP_XOR_WriteProcessMemory_08da {
  strings:
    $key_08da = { 5f a8 [2] 6d 8a [2] 6b bf [2] 45 bf [2] 7a a3 }

  condition:
    any of them
}