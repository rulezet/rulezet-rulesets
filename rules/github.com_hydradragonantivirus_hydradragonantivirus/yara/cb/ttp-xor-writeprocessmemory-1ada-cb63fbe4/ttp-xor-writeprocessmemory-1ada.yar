rule TTP_XOR_WriteProcessMemory_1ada {
  strings:
    $key_1ada = { 4d a8 [2] 7f 8a [2] 79 bf [2] 57 bf [2] 68 a3 }

  condition:
    any of them
}