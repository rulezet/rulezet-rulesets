rule TTP_XOR_WriteProcessMemory_c5ef {
  strings:
    $key_c5ef = { 92 9d [2] a0 bf [2] a6 8a [2] 88 8a [2] b7 96 }

  condition:
    any of them
}