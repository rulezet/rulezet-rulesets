rule TTP_XOR_WriteProcessMemory_446f {
  strings:
    $key_446f = { 13 1d [2] 21 3f [2] 27 0a [2] 09 0a [2] 36 16 }

  condition:
    any of them
}