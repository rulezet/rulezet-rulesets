rule TTP_XOR_WriteProcessMemory_33da {
  strings:
    $key_33da = { 64 a8 [2] 56 8a [2] 50 bf [2] 7e bf [2] 41 a3 }

  condition:
    any of them
}