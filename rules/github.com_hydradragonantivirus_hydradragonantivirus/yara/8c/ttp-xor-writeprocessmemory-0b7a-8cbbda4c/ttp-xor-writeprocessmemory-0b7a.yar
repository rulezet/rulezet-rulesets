rule TTP_XOR_WriteProcessMemory_0b7a {
  strings:
    $key_0b7a = { 5c 08 [2] 6e 2a [2] 68 1f [2] 46 1f [2] 79 03 }

  condition:
    any of them
}