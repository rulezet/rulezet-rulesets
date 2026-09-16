rule TTP_XOR_WriteProcessMemory_4cef {
  strings:
    $key_4cef = { 1b 9d [2] 29 bf [2] 2f 8a [2] 01 8a [2] 3e 96 }

  condition:
    any of them
}