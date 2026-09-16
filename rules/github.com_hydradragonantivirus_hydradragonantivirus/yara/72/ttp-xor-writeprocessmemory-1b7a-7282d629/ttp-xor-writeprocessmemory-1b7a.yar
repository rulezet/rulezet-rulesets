rule TTP_XOR_WriteProcessMemory_1b7a {
  strings:
    $key_1b7a = { 4c 08 [2] 7e 2a [2] 78 1f [2] 56 1f [2] 69 03 }

  condition:
    any of them
}