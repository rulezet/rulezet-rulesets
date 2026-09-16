rule TTP_XOR_WriteProcessMemory_d2ef {
  strings:
    $key_d2ef = { 85 9d [2] b7 bf [2] b1 8a [2] 9f 8a [2] a0 96 }

  condition:
    any of them
}