rule TTP_XOR_WriteProcessMemory_36ef {
  strings:
    $key_36ef = { 61 9d [2] 53 bf [2] 55 8a [2] 7b 8a [2] 44 96 }

  condition:
    any of them
}