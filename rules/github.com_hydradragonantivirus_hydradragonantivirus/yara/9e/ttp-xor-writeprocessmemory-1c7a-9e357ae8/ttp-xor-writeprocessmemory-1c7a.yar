rule TTP_XOR_WriteProcessMemory_1c7a {
  strings:
    $key_1c7a = { 4b 08 [2] 79 2a [2] 7f 1f [2] 51 1f [2] 6e 03 }

  condition:
    any of them
}