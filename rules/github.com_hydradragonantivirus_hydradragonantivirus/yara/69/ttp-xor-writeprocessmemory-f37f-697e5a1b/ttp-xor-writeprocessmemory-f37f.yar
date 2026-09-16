rule TTP_XOR_WriteProcessMemory_f37f {
  strings:
    $key_f37f = { a4 0d [2] 96 2f [2] 90 1a [2] be 1a [2] 81 06 }

  condition:
    any of them
}