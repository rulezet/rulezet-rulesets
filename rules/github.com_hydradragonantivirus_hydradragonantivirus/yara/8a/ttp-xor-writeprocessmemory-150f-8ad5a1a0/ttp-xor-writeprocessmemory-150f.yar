rule TTP_XOR_WriteProcessMemory_150f {
  strings:
    $key_150f = { 42 7d [2] 70 5f [2] 76 6a [2] 58 6a [2] 67 76 }

  condition:
    any of them
}