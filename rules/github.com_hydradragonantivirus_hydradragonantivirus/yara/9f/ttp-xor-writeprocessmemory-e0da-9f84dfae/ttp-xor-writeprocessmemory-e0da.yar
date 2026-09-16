rule TTP_XOR_WriteProcessMemory_e0da {
  strings:
    $key_e0da = { b7 a8 [2] 85 8a [2] 83 bf [2] ad bf [2] 92 a3 }

  condition:
    any of them
}