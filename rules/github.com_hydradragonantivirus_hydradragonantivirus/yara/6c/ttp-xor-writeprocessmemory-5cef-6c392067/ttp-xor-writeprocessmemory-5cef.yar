rule TTP_XOR_WriteProcessMemory_5cef {
  strings:
    $key_5cef = { 0b 9d [2] 39 bf [2] 3f 8a [2] 11 8a [2] 2e 96 }

  condition:
    any of them
}