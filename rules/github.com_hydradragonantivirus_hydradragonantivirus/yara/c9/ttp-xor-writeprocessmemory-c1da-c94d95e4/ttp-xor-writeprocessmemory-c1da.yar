rule TTP_XOR_WriteProcessMemory_c1da {
  strings:
    $key_c1da = { 96 a8 [2] a4 8a [2] a2 bf [2] 8c bf [2] b3 a3 }

  condition:
    any of them
}