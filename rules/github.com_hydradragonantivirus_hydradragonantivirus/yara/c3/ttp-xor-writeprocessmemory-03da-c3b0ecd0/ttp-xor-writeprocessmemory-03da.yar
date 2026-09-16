rule TTP_XOR_WriteProcessMemory_03da {
  strings:
    $key_03da = { 54 a8 [2] 66 8a [2] 60 bf [2] 4e bf [2] 71 a3 }

  condition:
    any of them
}