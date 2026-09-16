rule TTP_XOR_WriteProcessMemory_d5da {
  strings:
    $key_d5da = { 82 a8 [2] b0 8a [2] b6 bf [2] 98 bf [2] a7 a3 }

  condition:
    any of them
}