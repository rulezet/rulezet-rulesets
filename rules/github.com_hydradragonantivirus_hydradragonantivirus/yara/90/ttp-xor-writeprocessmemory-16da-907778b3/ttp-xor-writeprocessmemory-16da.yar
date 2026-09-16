rule TTP_XOR_WriteProcessMemory_16da {
  strings:
    $key_16da = { 41 a8 [2] 73 8a [2] 75 bf [2] 5b bf [2] 64 a3 }

  condition:
    any of them
}