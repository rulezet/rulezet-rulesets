rule TTP_XOR_WriteProcessMemory_0aef {
  strings:
    $key_0aef = { 5d 9d [2] 6f bf [2] 69 8a [2] 47 8a [2] 78 96 }

  condition:
    any of them
}