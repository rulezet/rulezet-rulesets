rule TTP_XOR_WriteProcessMemory_27ef {
  strings:
    $key_27ef = { 70 9d [2] 42 bf [2] 44 8a [2] 6a 8a [2] 55 96 }

  condition:
    any of them
}