rule TTP_XOR_WriteProcessMemory_53da {
  strings:
    $key_53da = { 04 a8 [2] 36 8a [2] 30 bf [2] 1e bf [2] 21 a3 }

  condition:
    any of them
}