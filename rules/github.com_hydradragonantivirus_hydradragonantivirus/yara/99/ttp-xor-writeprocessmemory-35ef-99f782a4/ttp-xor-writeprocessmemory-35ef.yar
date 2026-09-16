rule TTP_XOR_WriteProcessMemory_35ef {
  strings:
    $key_35ef = { 62 9d [2] 50 bf [2] 56 8a [2] 78 8a [2] 47 96 }

  condition:
    any of them
}