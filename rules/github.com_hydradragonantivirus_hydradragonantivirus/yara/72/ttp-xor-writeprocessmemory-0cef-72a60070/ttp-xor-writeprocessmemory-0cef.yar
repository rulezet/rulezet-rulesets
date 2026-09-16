rule TTP_XOR_WriteProcessMemory_0cef {
  strings:
    $key_0cef = { 5b 9d [2] 69 bf [2] 6f 8a [2] 41 8a [2] 7e 96 }

  condition:
    any of them
}