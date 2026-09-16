rule TTP_XOR_WriteProcessMemory_01da {
  strings:
    $key_01da = { 56 a8 [2] 64 8a [2] 62 bf [2] 4c bf [2] 73 a3 }

  condition:
    any of them
}