rule TTP_XOR_WriteProcessMemory_274a {
  strings:
    $key_274a = { 70 38 [2] 42 1a [2] 44 2f [2] 6a 2f [2] 55 33 }

  condition:
    any of them
}