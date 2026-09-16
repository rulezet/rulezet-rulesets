rule TTP_XOR_WriteProcessMemory_456f {
  strings:
    $key_456f = { 12 1d [2] 20 3f [2] 26 0a [2] 08 0a [2] 37 16 }

  condition:
    any of them
}