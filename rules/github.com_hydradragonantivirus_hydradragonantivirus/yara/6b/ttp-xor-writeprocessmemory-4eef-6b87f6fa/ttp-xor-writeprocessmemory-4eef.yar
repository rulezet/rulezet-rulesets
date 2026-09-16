rule TTP_XOR_WriteProcessMemory_4eef {
  strings:
    $key_4eef = { 19 9d [2] 2b bf [2] 2d 8a [2] 03 8a [2] 3c 96 }

  condition:
    any of them
}