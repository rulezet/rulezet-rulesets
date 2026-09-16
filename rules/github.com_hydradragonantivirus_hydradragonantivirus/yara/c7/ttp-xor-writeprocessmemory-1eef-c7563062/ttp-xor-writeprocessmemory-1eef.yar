rule TTP_XOR_WriteProcessMemory_1eef {
  strings:
    $key_1eef = { 49 9d [2] 7b bf [2] 7d 8a [2] 53 8a [2] 6c 96 }

  condition:
    any of them
}