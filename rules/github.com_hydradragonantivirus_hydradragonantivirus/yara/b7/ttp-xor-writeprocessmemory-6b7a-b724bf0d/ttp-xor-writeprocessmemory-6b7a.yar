rule TTP_XOR_WriteProcessMemory_6b7a {
  strings:
    $key_6b7a = { 3c 08 [2] 0e 2a [2] 08 1f [2] 26 1f [2] 19 03 }

  condition:
    any of them
}