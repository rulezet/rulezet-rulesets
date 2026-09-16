rule TTP_XOR_WriteProcessMemory_157f {
  strings:
    $key_157f = { 42 0d [2] 70 2f [2] 76 1a [2] 58 1a [2] 67 06 }

  condition:
    any of them
}