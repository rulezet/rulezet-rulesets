rule TTP_XOR_WriteProcessMemory_646a {
  strings:
    $key_646a = { 33 18 [2] 01 3a [2] 07 0f [2] 29 0f [2] 16 13 }

  condition:
    any of them
}