rule TTP_XOR_WriteProcessMemory_257f {
  strings:
    $key_257f = { 72 0d [2] 40 2f [2] 46 1a [2] 68 1a [2] 57 06 }

  condition:
    any of them
}