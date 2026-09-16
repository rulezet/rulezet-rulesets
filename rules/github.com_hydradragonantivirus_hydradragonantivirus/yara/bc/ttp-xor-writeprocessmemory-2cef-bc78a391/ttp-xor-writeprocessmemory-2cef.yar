rule TTP_XOR_WriteProcessMemory_2cef {
  strings:
    $key_2cef = { 7b 9d [2] 49 bf [2] 4f 8a [2] 61 8a [2] 5e 96 }

  condition:
    any of them
}