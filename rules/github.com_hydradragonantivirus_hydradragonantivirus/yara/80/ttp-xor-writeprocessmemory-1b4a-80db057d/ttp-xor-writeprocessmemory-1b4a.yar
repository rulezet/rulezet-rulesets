rule TTP_XOR_WriteProcessMemory_1b4a {
  strings:
    $key_1b4a = { 4c 38 [2] 7e 1a [2] 78 2f [2] 56 2f [2] 69 33 }

  condition:
    any of them
}