rule TTP_XOR_WriteProcessMemory_252f {
  strings:
    $key_252f = { 72 5d [2] 40 7f [2] 46 4a [2] 68 4a [2] 57 56 }

  condition:
    any of them
}