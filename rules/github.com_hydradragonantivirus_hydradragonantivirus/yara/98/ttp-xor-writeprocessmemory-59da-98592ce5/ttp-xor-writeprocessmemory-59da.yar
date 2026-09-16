rule TTP_XOR_WriteProcessMemory_59da {
  strings:
    $key_59da = { 0e a8 [2] 3c 8a [2] 3a bf [2] 14 bf [2] 2b a3 }

  condition:
    any of them
}