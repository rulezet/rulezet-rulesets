rule TTP_XOR_WriteProcessMemory_554a {
  strings:
    $key_554a = { 02 38 [2] 30 1a [2] 36 2f [2] 18 2f [2] 27 33 }

  condition:
    any of them
}