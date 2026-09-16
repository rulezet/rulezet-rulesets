rule TTP_XOR_WriteProcessMemory_d1da {
  strings:
    $key_d1da = { 86 a8 [2] b4 8a [2] b2 bf [2] 9c bf [2] a3 a3 }

  condition:
    any of them
}