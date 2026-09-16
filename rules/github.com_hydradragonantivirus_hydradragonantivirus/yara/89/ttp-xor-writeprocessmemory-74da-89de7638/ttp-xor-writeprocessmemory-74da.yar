rule TTP_XOR_WriteProcessMemory_74da {
  strings:
    $key_74da = { 23 a8 [2] 11 8a [2] 17 bf [2] 39 bf [2] 06 a3 }

  condition:
    any of them
}