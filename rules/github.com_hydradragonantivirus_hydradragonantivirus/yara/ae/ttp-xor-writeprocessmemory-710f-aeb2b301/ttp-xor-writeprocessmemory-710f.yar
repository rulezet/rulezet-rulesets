rule TTP_XOR_WriteProcessMemory_710f {
  strings:
    $key_710f = { 26 7d [2] 14 5f [2] 12 6a [2] 3c 6a [2] 03 76 }

  condition:
    any of them
}