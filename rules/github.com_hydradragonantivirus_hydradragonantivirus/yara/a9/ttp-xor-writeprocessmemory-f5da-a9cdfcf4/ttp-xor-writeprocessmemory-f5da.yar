rule TTP_XOR_WriteProcessMemory_f5da {
  strings:
    $key_f5da = { a2 a8 [2] 90 8a [2] 96 bf [2] b8 bf [2] 87 a3 }

  condition:
    any of them
}