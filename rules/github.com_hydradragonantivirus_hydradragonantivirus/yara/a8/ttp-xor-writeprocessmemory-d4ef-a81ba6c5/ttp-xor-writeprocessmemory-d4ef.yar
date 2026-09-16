rule TTP_XOR_WriteProcessMemory_d4ef {
  strings:
    $key_d4ef = { 83 9d [2] b1 bf [2] b7 8a [2] 99 8a [2] a6 96 }

  condition:
    any of them
}