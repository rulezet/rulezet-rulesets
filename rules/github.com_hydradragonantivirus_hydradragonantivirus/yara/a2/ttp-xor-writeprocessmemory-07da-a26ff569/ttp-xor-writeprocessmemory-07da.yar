rule TTP_XOR_WriteProcessMemory_07da {
  strings:
    $key_07da = { 50 a8 [2] 62 8a [2] 64 bf [2] 4a bf [2] 75 a3 }

  condition:
    any of them
}