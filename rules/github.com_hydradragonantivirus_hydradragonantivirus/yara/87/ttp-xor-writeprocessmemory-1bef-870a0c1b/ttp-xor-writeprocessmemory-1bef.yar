rule TTP_XOR_WriteProcessMemory_1bef {
  strings:
    $key_1bef = { 4c 9d [2] 7e bf [2] 78 8a [2] 56 8a [2] 69 96 }

  condition:
    any of them
}