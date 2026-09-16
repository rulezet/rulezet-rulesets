rule TTP_XOR_WriteProcessMemory_13da {
  strings:
    $key_13da = { 44 a8 [2] 76 8a [2] 70 bf [2] 5e bf [2] 61 a3 }

  condition:
    any of them
}