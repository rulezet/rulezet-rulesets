rule TTP_XOR_WriteProcessMemory_d0da {
  strings:
    $key_d0da = { 87 a8 [2] b5 8a [2] b3 bf [2] 9d bf [2] a2 a3 }

  condition:
    any of them
}