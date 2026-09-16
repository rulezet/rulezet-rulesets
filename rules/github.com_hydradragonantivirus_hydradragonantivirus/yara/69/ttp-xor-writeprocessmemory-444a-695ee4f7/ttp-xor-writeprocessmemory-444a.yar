rule TTP_XOR_WriteProcessMemory_444a {
  strings:
    $key_444a = { 13 38 [2] 21 1a [2] 27 2f [2] 09 2f [2] 36 33 }

  condition:
    any of them
}