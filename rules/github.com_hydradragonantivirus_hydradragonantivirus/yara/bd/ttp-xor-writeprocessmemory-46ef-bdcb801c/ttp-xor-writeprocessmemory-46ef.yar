rule TTP_XOR_WriteProcessMemory_46ef {
  strings:
    $key_46ef = { 11 9d [2] 23 bf [2] 25 8a [2] 0b 8a [2] 34 96 }

  condition:
    any of them
}