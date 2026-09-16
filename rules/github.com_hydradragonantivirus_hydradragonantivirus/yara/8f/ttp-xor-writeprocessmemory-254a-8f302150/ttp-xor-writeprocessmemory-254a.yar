rule TTP_XOR_WriteProcessMemory_254a {
  strings:
    $key_254a = { 72 38 [2] 40 1a [2] 46 2f [2] 68 2f [2] 57 33 }

  condition:
    any of them
}