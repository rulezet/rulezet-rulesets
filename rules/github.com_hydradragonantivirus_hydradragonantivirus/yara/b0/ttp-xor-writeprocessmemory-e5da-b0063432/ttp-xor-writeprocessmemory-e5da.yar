rule TTP_XOR_WriteProcessMemory_e5da {
  strings:
    $key_e5da = { b2 a8 [2] 80 8a [2] 86 bf [2] a8 bf [2] 97 a3 }

  condition:
    any of them
}