rule TTP_XOR_WriteProcessMemory_415a {
  strings:
    $key_415a = { 16 28 [2] 24 0a [2] 22 3f [2] 0c 3f [2] 33 23 }

  condition:
    any of them
}