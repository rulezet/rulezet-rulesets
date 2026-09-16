rule TTP_XOR_WriteProcessMemory_5aef {
  strings:
    $key_5aef = { 0d 9d [2] 3f bf [2] 39 8a [2] 17 8a [2] 28 96 }

  condition:
    any of them
}