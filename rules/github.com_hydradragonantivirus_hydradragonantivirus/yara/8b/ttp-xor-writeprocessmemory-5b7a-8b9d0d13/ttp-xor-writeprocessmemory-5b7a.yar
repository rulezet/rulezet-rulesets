rule TTP_XOR_WriteProcessMemory_5b7a {
  strings:
    $key_5b7a = { 0c 08 [2] 3e 2a [2] 38 1f [2] 16 1f [2] 29 03 }

  condition:
    any of them
}