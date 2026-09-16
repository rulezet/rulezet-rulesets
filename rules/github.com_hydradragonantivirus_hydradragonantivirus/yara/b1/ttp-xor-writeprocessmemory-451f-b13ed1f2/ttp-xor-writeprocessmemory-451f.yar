rule TTP_XOR_WriteProcessMemory_451f {
  strings:
    $key_451f = { 12 6d [2] 20 4f [2] 26 7a [2] 08 7a [2] 37 66 }

  condition:
    any of them
}