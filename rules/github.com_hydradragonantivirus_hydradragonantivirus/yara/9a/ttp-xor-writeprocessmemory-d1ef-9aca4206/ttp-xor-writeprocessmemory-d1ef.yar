rule TTP_XOR_WriteProcessMemory_d1ef {
  strings:
    $key_d1ef = { 86 9d [2] b4 bf [2] b2 8a [2] 9c 8a [2] a3 96 }

  condition:
    any of them
}