rule TTP_XOR_WriteProcessMemory_14ef {
  strings:
    $key_14ef = { 43 9d [2] 71 bf [2] 77 8a [2] 59 8a [2] 66 96 }

  condition:
    any of them
}