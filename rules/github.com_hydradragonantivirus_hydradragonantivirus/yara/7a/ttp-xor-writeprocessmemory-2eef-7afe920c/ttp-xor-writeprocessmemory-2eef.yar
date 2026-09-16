rule TTP_XOR_WriteProcessMemory_2eef {
  strings:
    $key_2eef = { 79 9d [2] 4b bf [2] 4d 8a [2] 63 8a [2] 5c 96 }

  condition:
    any of them
}