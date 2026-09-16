rule TTP_XOR_WriteProcessMemory_c6da {
  strings:
    $key_c6da = { 91 a8 [2] a3 8a [2] a5 bf [2] 8b bf [2] b4 a3 }

  condition:
    any of them
}