rule TTP_XOR_WriteProcessMemory_e47f {
  strings:
    $key_e47f = { b3 0d [2] 81 2f [2] 87 1a [2] a9 1a [2] 96 06 }

  condition:
    any of them
}