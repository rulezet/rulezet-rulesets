rule TTP_XOR_WriteProcessMemory_05da {
  strings:
    $key_05da = { 52 a8 [2] 60 8a [2] 66 bf [2] 48 bf [2] 77 a3 }

  condition:
    any of them
}