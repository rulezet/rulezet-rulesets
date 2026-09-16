rule TTP_XOR_WriteProcessMemory_772f {
  strings:
    $key_772f = { 20 5d [2] 12 7f [2] 14 4a [2] 3a 4a [2] 05 56 }

  condition:
    any of them
}