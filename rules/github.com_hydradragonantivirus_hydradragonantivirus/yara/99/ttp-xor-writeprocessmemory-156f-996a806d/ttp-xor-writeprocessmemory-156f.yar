rule TTP_XOR_WriteProcessMemory_156f {
  strings:
    $key_156f = { 42 1d [2] 70 3f [2] 76 0a [2] 58 0a [2] 67 16 }

  condition:
    any of them
}