rule TTP_XOR_WriteProcessMemory_f57f {
  strings:
    $key_f57f = { a2 0d [2] 90 2f [2] 96 1a [2] b8 1a [2] 87 06 }

  condition:
    any of them
}