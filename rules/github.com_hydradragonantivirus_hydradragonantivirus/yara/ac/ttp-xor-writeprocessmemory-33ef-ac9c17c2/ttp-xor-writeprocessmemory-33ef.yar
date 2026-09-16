rule TTP_XOR_WriteProcessMemory_33ef {
  strings:
    $key_33ef = { 64 9d [2] 56 bf [2] 50 8a [2] 7e 8a [2] 41 96 }

  condition:
    any of them
}