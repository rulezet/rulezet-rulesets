rule TTP_XOR_WriteProcessMemory_647a {
  strings:
    $key_647a = { 33 08 [2] 01 2a [2] 07 1f [2] 29 1f [2] 16 03 }

  condition:
    any of them
}