rule TTP_XOR_WriteProcessMemory_31ef {
  strings:
    $key_31ef = { 66 9d [2] 54 bf [2] 52 8a [2] 7c 8a [2] 43 96 }

  condition:
    any of them
}