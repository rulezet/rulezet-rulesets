rule TTP_XOR_WriteProcessMemory_7ada {
  strings:
    $key_7ada = { 2d a8 [2] 1f 8a [2] 19 bf [2] 37 bf [2] 08 a3 }

  condition:
    any of them
}