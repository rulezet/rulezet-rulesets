rule TTP_XOR_WriteProcessMemory_d6ef {
  strings:
    $key_d6ef = { 81 9d [2] b3 bf [2] b5 8a [2] 9b 8a [2] a4 96 }

  condition:
    any of them
}