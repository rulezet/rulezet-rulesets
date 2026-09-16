rule TTP_XOR_WriteProcessMemory_5d7a {
  strings:
    $key_5d7a = { 0a 08 [2] 38 2a [2] 3e 1f [2] 10 1f [2] 2f 03 }

  condition:
    any of them
}