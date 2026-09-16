rule TTP_XOR_WriteProcessMemory_056f {
  strings:
    $key_056f = { 52 1d [2] 60 3f [2] 66 0a [2] 48 0a [2] 77 16 }

  condition:
    any of them
}