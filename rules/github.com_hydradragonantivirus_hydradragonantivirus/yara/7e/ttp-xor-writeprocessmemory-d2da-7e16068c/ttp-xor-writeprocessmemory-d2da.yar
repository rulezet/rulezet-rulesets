rule TTP_XOR_WriteProcessMemory_d2da {
  strings:
    $key_d2da = { 85 a8 [2] b7 8a [2] b1 bf [2] 9f bf [2] a0 a3 }

  condition:
    any of them
}