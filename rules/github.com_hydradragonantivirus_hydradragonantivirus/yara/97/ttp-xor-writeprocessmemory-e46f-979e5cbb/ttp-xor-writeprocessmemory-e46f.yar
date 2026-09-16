rule TTP_XOR_WriteProcessMemory_e46f {
  strings:
    $key_e46f = { b3 1d [2] 81 3f [2] 87 0a [2] a9 0a [2] 96 16 }

  condition:
    any of them
}