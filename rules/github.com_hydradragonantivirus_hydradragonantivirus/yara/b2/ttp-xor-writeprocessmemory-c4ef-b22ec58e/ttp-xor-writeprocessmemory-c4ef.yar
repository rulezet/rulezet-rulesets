rule TTP_XOR_WriteProcessMemory_c4ef {
  strings:
    $key_c4ef = { 93 9d [2] a1 bf [2] a7 8a [2] 89 8a [2] b6 96 }

  condition:
    any of them
}