rule TTP_XOR_WriteProcessMemory_0460 {
  strings:
    $key_0460 = { 53 12 [2] 61 30 [2] 67 05 [2] 49 05 [2] 76 19 }

  condition:
    any of them
}