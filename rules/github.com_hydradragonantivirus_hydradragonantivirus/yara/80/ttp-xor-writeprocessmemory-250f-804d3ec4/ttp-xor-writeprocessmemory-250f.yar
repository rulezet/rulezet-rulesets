rule TTP_XOR_WriteProcessMemory_250f {
  strings:
    $key_250f = { 72 7d [2] 40 5f [2] 46 6a [2] 68 6a [2] 57 76 }

  condition:
    any of them
}