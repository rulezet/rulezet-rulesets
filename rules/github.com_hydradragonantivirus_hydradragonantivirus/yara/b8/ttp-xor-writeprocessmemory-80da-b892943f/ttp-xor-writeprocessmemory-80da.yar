rule TTP_XOR_WriteProcessMemory_80da {
  strings:
    $key_80da = { d7 a8 [2] e5 8a [2] e3 bf [2] cd bf [2] f2 a3 }

  condition:
    any of them
}