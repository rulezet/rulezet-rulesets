rule TTP_XOR_WriteProcessMemory_14da {
  strings:
    $key_14da = { 43 a8 [2] 71 8a [2] 77 bf [2] 59 bf [2] 66 a3 }

  condition:
    any of them
}