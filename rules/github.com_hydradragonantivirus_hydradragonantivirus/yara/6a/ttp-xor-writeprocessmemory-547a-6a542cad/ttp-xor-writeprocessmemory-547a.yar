rule TTP_XOR_WriteProcessMemory_547a {
  strings:
    $key_547a = { 03 08 [2] 31 2a [2] 37 1f [2] 19 1f [2] 26 03 }

  condition:
    any of them
}