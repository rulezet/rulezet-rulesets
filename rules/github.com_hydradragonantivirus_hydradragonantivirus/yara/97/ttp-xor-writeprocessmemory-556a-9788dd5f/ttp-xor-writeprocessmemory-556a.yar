rule TTP_XOR_WriteProcessMemory_556a {
  strings:
    $key_556a = { 02 18 [2] 30 3a [2] 36 0f [2] 18 0f [2] 27 13 }

  condition:
    any of them
}