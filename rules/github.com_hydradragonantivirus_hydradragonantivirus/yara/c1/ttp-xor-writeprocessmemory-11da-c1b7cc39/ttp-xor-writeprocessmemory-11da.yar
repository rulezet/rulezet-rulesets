rule TTP_XOR_WriteProcessMemory_11da {
  strings:
    $key_11da = { 46 a8 [2] 74 8a [2] 72 bf [2] 5c bf [2] 63 a3 }

  condition:
    any of them
}