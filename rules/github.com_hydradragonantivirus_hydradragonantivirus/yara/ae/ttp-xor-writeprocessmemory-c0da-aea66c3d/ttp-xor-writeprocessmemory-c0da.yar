rule TTP_XOR_WriteProcessMemory_c0da {
  strings:
    $key_c0da = { 97 a8 [2] a5 8a [2] a3 bf [2] 8d bf [2] b2 a3 }

  condition:
    any of them
}